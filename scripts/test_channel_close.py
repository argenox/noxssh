#!/usr/bin/env python3
"""Actual C channel-end/outer/completion blocks, with simulated transport/clock.

No credentials, child process or network. Real fast-PTY integration is covered
separately by ci_smoke_sshd.sh on an authorized Linux test host.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
from test_session_keepalive import braces


def function(source,name):
    m=re.search(r"static (?:uint32_t|netnox_return_t|void|int) "+re.escape(name)+r"\s*\(",source)
    if not m:raise ValueError("missing production function "+name)
    return braces(source,m.start())


def harness(source,header):
    names=("NETNOX_SSH_MSG_GLOBAL_REQUEST","NETNOX_SSH_MSG_REQUEST_FAILURE",
        "NETNOX_SSH_MSG_CHANNEL_EOF","NETNOX_SSH_MSG_CHANNEL_CLOSE",
        "NETNOX_SSH_MSG_CHANNEL_REQUEST","NETNOX_SSH_MSG_DISCONNECT")
    constants="\n".join(re.search(r"^#define "+n+r" .*",header,re.M)[0] for n in names)+"\n"
    helpers="\n".join(function(source,n) for n in ("netnox_ssh_write_u32_be",
        "netnox_ssh_read_u32_be","netnox_ssh_payload_append_u8","netnox_ssh_payload_append_u32",
        "netnox_ssh_payload_append_string","netnox_ssh_payload_read_u32",
        "srv_send_global_request_failure","srv_handle_global_request","srv_send_channel_eof",
        "srv_send_channel_close","srv_handle_channel_end","srv_begin_close_wait",
        "srv_wait_close_packet","srv_send_exit_status"))
    outer=source[source.index("netnox_return_t netnox_ssh_server_serve_one("):]
    end=braces(outer,outer.index("case NETNOX_SSH_MSG_CHANNEL_EOF:"))
    global_case=braces(outer,outer.index("case NETNOX_SSH_MSG_GLOBAL_REQUEST:"))
    disconnect=outer[outer.index("case NETNOX_SSH_MSG_DISCONNECT:"):outer.index("case NETNOX_SSH_MSG_IGNORE:")]
    session=source[source.index("static netnox_return_t srv_run_session_unix("):]
    completion=braces(session,session.index("if(output_eof && child_reaped)"))
    preamble=r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
// Standard native headers above keep their platform configuration; the
// extracted dispatch below selects the Unix branch being qualified.
#undef _WIN32
typedef int netnox_return_t;
#define NETNOX_RETURN_SUCCESS 0
#define NETNOX_RETURN_FAILED -1
#define NETNOX_RETURN_BAD_PARAM -2
typedef struct { int transport_fd; uint32_t local_channel_id,remote_channel_id;
 uint8_t channel_open; uint32_t unchanged; } netnox_ssh_server_t;
struct pollfd { int fd; short events,revents; };
#define POLLIN 1
#define POLLHUP 2
#define POLLERR 4
#define POLLNVAL 8
static uint64_t fake_now=100;
static int poll_rc=1,poll_events=POLLIN,poll_calls,poll_timeout;
static uint64_t srv_now_ms(void) {return fake_now;}
static int poll(struct pollfd *p,int count,int timeout) {
 if(count!=1) return -1;
 poll_calls++;poll_timeout=timeout;p->revents=(short)poll_events;return poll_rc;
}
static int sends,fail_at,closed_fd;
static uint8_t packets[8][128];static uint32_t packet_sizes[8];
static netnox_return_t srv_send_packet(netnox_ssh_server_t *s,const uint8_t *p,uint32_t n) {
 if(!s || sends>=8 || n>128) return -1;
 memcpy(packets[sends],p,n);packet_sizes[sends++]=n;
 return sends==fail_at ? -1 : 0;
}
static int close(int fd) {closed_fd=fd;return 0;}
#define WIFEXITED(s) (((s)&0x7f)==0)
#define WEXITSTATUS(s) (((s)>>8)&0xff)
#define WTERMSIG(s) ((s)&0x7f)
'''
    fixture=r'''
// 777 means the finite injected sequence ended while the connection stays
// alive; it is deliberately not success/closed. No drain timeout is invented.
static uint64_t observed_deadline;
static int consumed;
static int outer_packets(netnox_ssh_server_t *s,const uint8_t **p,const uint32_t *n,
                         int count,uint64_t initial_deadline) {
 uint64_t close_deadline_ms=initial_deadline;
 consumed=0;
 for(int i=0;i<count;i++) {
  const uint8_t *payload=p[i];uint32_t payload_len=n[i];consumed++;
  switch(payload[0]) { END_CASE GLOBAL_CASE DISCONNECT_CASE default:return -1; }
 }
 observed_deadline=close_deadline_ms;return 777;
}
static int completed(netnox_ssh_server_t *s,int status) {
 int output_eof=1,child_reaped=1,child_fd=99;
 for(;;) { COMPLETION_BLOCK break; }
 return -1;
}
static unsigned tests;
#define CHECK(expr) do {tests++;if(!(expr)) {fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#expr);return 1;}}while(0)
static void fresh(netnox_ssh_server_t *s,int open) {
 memset(s,0,sizeof(*s));s->transport_fd=6;s->local_channel_id=0;s->remote_channel_id=7;
 s->channel_open=(uint8_t)open;s->unchanged=0x12345678;sends=fail_at=closed_fd=0;
 fake_now=100;poll_rc=1;poll_events=POLLIN;poll_calls=poll_timeout=0;
}
int main(void) {
 netnox_ssh_server_t state,*s=&state;
 uint8_t eof[]={96,0,0,0,0},cl[]={97,0,0,0,0},bye[]={1},wrong[]={96,0,0,0,1};
 const uint8_t *p[]={eof,cl,bye};uint32_t n[]={5,5,1};
 fresh(s,1);CHECK(outer_packets(s,p,n,1,0)==777);CHECK(s->channel_open==1);
 CHECK(sends==0 && consumed==1 && observed_deadline==0);
 fresh(s,1);CHECK(outer_packets(s,p,n,2,0)==777);CHECK(s->channel_open==0);
 CHECK(sends==1 && packets[0][0]==97 && packet_sizes[0]==5 && packets[0][4]==7);
 CHECK(observed_deadline==10100 && consumed==2);
 fresh(s,1);CHECK(outer_packets(s,p,n,3,0)==0);CHECK(consumed==3 && sends==1);
 fresh(s,0);CHECK(outer_packets(s,p,n,3,10100)==0);CHECK(consumed==3 && sends==0);
 const uint8_t *duplicates[]={cl,eof,cl};uint32_t dn[]={5,5,5};
 fresh(s,1);CHECK(outer_packets(s,duplicates,dn,3,0)==777);
 CHECK(sends==1 && observed_deadline==10100 && s->channel_open==0);
 uint8_t keepalive[27]={80,0,0,0,21};memcpy(keepalive+5,"keepalive@openssh.com",21);keepalive[26]=1;
 const uint8_t *with_probe[]={cl,keepalive,eof,cl};uint32_t pn[]={5,27,5,5};
 fresh(s,1);CHECK(outer_packets(s,with_probe,pn,4,0)==777);
 CHECK(sends==2 && packets[0][0]==97 && packets[1][0]==82 && observed_deadline==10100);
 fresh(s,1);fail_at=1;CHECK(outer_packets(s,p+1,n+1,1,0)<0);CHECK(s->channel_open==1);
 fresh(s,1);CHECK(srv_handle_channel_end(s,wrong,5)<0);CHECK(sends==0 && s->channel_open==1);
 for(unsigned length=0;length<5;length++) CHECK(srv_handle_channel_end(s,eof,length)<0);
 uint8_t extra[]={96,0,0,0,0,1};CHECK(srv_handle_channel_end(s,extra,6)<0);
 CHECK(srv_handle_channel_end(NULL,eof,5)<0);CHECK(srv_handle_channel_end(s,NULL,5)<0);
 puts("PASS actual outer EOF stays open, CLOSE reply-once, queued EOF/CLOSE before DISCONNECT, framing/recipient/send error");
 uint64_t deadline=0;CHECK(srv_begin_close_wait(&deadline)==0 && deadline==10100);
 fake_now=9000;CHECK(srv_begin_close_wait(&deadline)==0 && deadline==10100);
 CHECK(srv_wait_close_packet(s,deadline)==1 && poll_timeout==1100);
 poll_events=POLLIN|POLLHUP;CHECK(srv_wait_close_packet(s,deadline)==1);
 poll_events=POLLHUP;CHECK(srv_wait_close_packet(s,deadline)==0);
 poll_events=POLLERR;CHECK(srv_wait_close_packet(s,deadline)<0);
 poll_events=POLLNVAL;CHECK(srv_wait_close_packet(s,deadline)<0);
 poll_rc=-1;errno=EINTR;CHECK(srv_wait_close_packet(s,deadline)==2);
 errno=EIO;CHECK(srv_wait_close_packet(s,deadline)<0);
 poll_rc=0;CHECK(srv_wait_close_packet(s,deadline)==0);
 fake_now=deadline;int calls=poll_calls;CHECK(srv_wait_close_packet(s,deadline)==0 && poll_calls==calls);
 fake_now=UINT64_MAX;deadline=0;CHECK(srv_begin_close_wait(&deadline)<0 && deadline==0);
 CHECK(srv_wait_close_packet(s,100)<0);
 puts("PASS fixed non-extending close deadline, readable+hangup drains data, idle expiry, EINTR/error/clock failure");
 for(int fail=0;fail<=3;fail++) {
  fresh(s,1);fail_at=fail;int rc=completed(s,9<<8);
  if(fail) {CHECK(rc<0 && sends==fail && closed_fd==0 && s->channel_open==1);}
  else {CHECK(rc==0 && sends==3 && closed_fd==99 && s->channel_open==0);
   CHECK(packets[0][0]==98 && packets[1][0]==96 && packets[2][0]==97);
   CHECK(packet_sizes[0]==25 && packets[0][24]==9);}
  CHECK(s->unchanged==0x12345678);
 }
 puts("PASS actual completion exit-status9/EOF/CLOSE order, each failed send cannot report success");
 printf("PASS %u native actual-C close checks; no Unix/SSH/child integration\n",tests);return 0;
}
'''.replace("END_CASE",end).replace("GLOBAL_CASE",global_case).replace("DISCONNECT_CASE",disconnect).replace("COMPLETION_BLOCK",completion)
    return preamble+constants+helpers+fixture


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root",type=Path,default=Path(__file__).resolve().parent.parent)
    p.add_argument("--fixture-parent",type=Path,required=True)
    p.add_argument("--cc",default=os.environ.get("NOXSSH_FIXTURE_CC") or (
        "D:/Argenox_FPGA/builds/kc705-mpunoxv/toolchains/msys2_overlay/mingw64/bin/gcc.exe" if os.name=="nt" else "cc"))
    a=p.parse_args();source=(a.source_root/"common/noxssh_server.c").read_text()
    code=harness(source,(a.source_root/"common/noxssh_common.h").read_text())
    a.fixture_parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="noxssh-close-",dir=a.fixture_parent) as scratch:
        root=Path(scratch);c=root/"actual.c";exe=root/"actual.exe"
        c.write_text(code,encoding="ascii",newline="\n")
        env=os.environ.copy();env["PATH"]=str(Path(a.cc).parent)+os.pathsep+env["PATH"]
        subprocess.run([a.cc,"-std=c99","-O2","-Wall","-Wextra","-Werror",str(c),"-o",str(exe)],check=True,env=env)
        subprocess.run([str(exe)],check=True,env=env)


if __name__=="__main__":main()
