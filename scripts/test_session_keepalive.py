#!/usr/bin/env python3
"""Compile actual global-request parser and both call-site blocks with transport stubs.

No SSH, keys, accounts, forked child, board or real network is used. The separate
Linux ci_smoke_sshd.sh exercises real quiet child/SSH transport integration.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def braces(source, start):
    first=source.index("{",start)
    depth=1;end=first+1
    while depth:
        if source[end]=="{":depth+=1
        elif source[end]=="}":depth-=1
        end+=1
    return source[start:end]


def function(source, name):
    match=re.search(r"static (?:uint32_t|netnox_return_t) "+re.escape(name)+r"\s*\(",source)
    if not match:raise ValueError("missing production function "+name)
    return braces(source,match.start())


def harness(source, constants):
    active_start=source.index("static netnox_return_t srv_run_session_unix(")
    active=braces(source,active_start)
    # Compile the actual call-site block, not a separately handwritten model.
    session=braces(active,active.index("if(payload[0] == NETNOX_SSH_MSG_GLOBAL_REQUEST)"))
    outer=source[source.index("netnox_return_t netnox_ssh_server_serve_one("):]
    outer=braces(outer,outer.index("case NETNOX_SSH_MSG_GLOBAL_REQUEST:"))
    preamble=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int netnox_return_t;
#define NETNOX_RETURN_SUCCESS 0
#define NETNOX_RETURN_FAILED -1
#define NETNOX_RETURN_BAD_PARAM -2
typedef struct { uint32_t unchanged; } netnox_ssh_server_t;
static int sends, fail_send;
static uint8_t sent[8];
static netnox_return_t srv_send_packet(netnox_ssh_server_t *s,const uint8_t *p,uint32_t len)
{
 if(!s || len!=1 || sends>=8) return NETNOX_RETURN_FAILED;
 sent[sends++]=p[0];
 return fail_send ? NETNOX_RETURN_FAILED : NETNOX_RETURN_SUCCESS;
}
'''
    extracted="\n".join(function(source,n) for n in ("netnox_ssh_read_u32_be",
        "netnox_ssh_payload_read_u32","srv_send_global_request_failure","srv_handle_global_request"))
    wrappers='''
static int session_call(netnox_ssh_server_t *s,const uint8_t *payload,uint32_t len,int repeat)
{
 int probe;
 if(!len) return NETNOX_RETURN_FAILED;
 for(probe=0;probe<repeat;probe++) {
 SESSION_BLOCK
 else return NETNOX_RETURN_FAILED;
 }
 return probe==repeat ? NETNOX_RETURN_SUCCESS : NETNOX_RETURN_FAILED;
}
static int outer_call(netnox_ssh_server_t *s,const uint8_t *payload,uint32_t payload_len,int repeat)
{
 if(!payload_len) return NETNOX_RETURN_FAILED;
 for(int probe=0;probe<repeat;probe++) {
 switch(payload[0]) { OUTER_BLOCK default:return NETNOX_RETURN_FAILED; }
 }
 return NETNOX_RETURN_SUCCESS;
}
int main(int argc,char **argv)
{
 uint8_t data[256]={0};uint32_t len;
 netnox_ssh_server_t state={0x12345678},*s=&state;
 if(argc!=5 || strlen(argv[2])%2 || strlen(argv[2])>sizeof(data)*2) return 99;
 len=(uint32_t)(strlen(argv[2])/2);
 for(uint32_t i=0;i<len;i++) { unsigned byte;if(sscanf(argv[2]+2*i,"%2x",&byte)!=1) return 98;data[i]=(uint8_t)byte; }
 fail_send=atoi(argv[3]);int repeat=atoi(argv[4]),rc;
 if(repeat<1 || repeat>4) return 97;
 if(!strcmp(argv[1],"session")) rc=session_call(s,data,len,repeat);
 else if(!strcmp(argv[1],"outer")) rc=outer_call(s,data,len,repeat);
 else if(!strcmp(argv[1],"null-state")) rc=srv_handle_global_request(NULL,data,len);
 else if(!strcmp(argv[1],"null-packet")) rc=srv_handle_global_request(s,NULL,len);
 else {
  rc=NETNOX_RETURN_SUCCESS;
  for(int probe=0;probe<repeat;probe++) {
   rc=srv_handle_global_request(s,data,len);
   if(rc!=NETNOX_RETURN_SUCCESS) break;
  }
 }
 printf("%d %d %u",rc,sends,state.unchanged);
 for(int i=0;i<sends;i++) printf(" %u",sent[i]);
 puts("");return 0;
}
'''.replace("SESSION_BLOCK",session).replace("OUTER_BLOCK",outer)
    return preamble+constants+extracted+wrappers


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root",type=Path,default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--fixture-parent",type=Path,required=True)
    parser.add_argument("--cc",default=os.environ.get("NOXSSH_FIXTURE_CC") or
        ("D:/Argenox_FPGA/builds/kc705-mpunoxv/toolchains/msys2_overlay/mingw64/bin/gcc.exe"
         if os.name=="nt" else "cc"))
    args=parser.parse_args()
    source=(args.source_root/"common/noxssh_server.c").read_text()
    header=(args.source_root/"common/noxssh_common.h").read_text()
    constants="\n".join(re.search(r"^#define "+n+r" .*",header,re.M)[0]
        for n in ("NETNOX_SSH_MSG_GLOBAL_REQUEST","NETNOX_SSH_MSG_REQUEST_FAILURE"))+"\n"
    code=harness(source,constants)
    args.fixture_parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="noxssh-keepalive-",dir=args.fixture_parent) as scratch:
        root=Path(scratch);c=root/"actual.c";exe=root/"actual.exe"
        c.write_text(code,encoding="ascii",newline="\n")
        env=os.environ.copy();env["PATH"]=str(Path(args.cc).parent)+os.pathsep+env["PATH"]
        command=[args.cc,"-std=c99","-O2","-Wall","-Wextra","-Werror",str(c),"-o",str(exe)]
        subprocess.run(command,check=True,env=env)
        def run(mode,packet,want_sends,success=True,fail=0,repeat=1):
            out=subprocess.check_output([str(exe),mode,packet.hex(),str(fail),str(repeat)],env=env,text=True)
            values=[int(v) for v in out.split()]
            assert (values[0]==0)==success,(mode,packet,out)
            assert values[1]==want_sends and values[2]==0x12345678,(mode,packet,out)
            assert values[3:]==[82]*want_sends,(mode,packet,out)
        def frame(name=b"keepalive@openssh.com",want=1,body=b""):
            return bytes([80])+len(name).to_bytes(4,"big")+name+bytes([want])+body
        tests=0
        for mode in ("session","outer","helper"):
            for want in (0,1,255):
                run(mode,frame(want=want),int(want!=0));tests+=1
            run(mode,frame(),4,repeat=4);tests+=1
            run(mode,frame(name=b"unsupported@test",body=b"opaque arguments"),1);tests+=1
            run(mode,frame(),1,success=False,fail=1);tests+=1
            malformed=[b"",b"\x4f\0\0\0\1x\1",frame(name=b""),b"\x50\xff\xff\xff\xffx\1"]
            malformed += [frame()[:n] for n in range(1,len(frame()))]
            for packet in malformed:run(mode,packet,0,success=False);tests+=1
            print("PASS",mode,"want-reply0/1/nonzero, four quiet probes, opaque unsupported body, send failure, malformed/truncated/u32-overflow")
        run("null-state",frame(),0,success=False);run("null-packet",frame(),0,success=False);tests+=2
        print(f"PASS {tests} actual-C transport-stub cases; no credentials, process or network integration")


if __name__=="__main__":main()
