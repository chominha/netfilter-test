#include <stdio.h>                  // 표준 입출력 함수 사용 (printf, fprintf 등)
#include <stdlib.h>                 // 일반 유틸리티 함수 (exit, system 등)
#include <unistd.h>                 // POSIX API (read, write, close 등)
#include <netinet/in.h>             // 인터넷 주소 구조체, ntohl 등 네트워크 함수
#include <linux/types.h>            // 리눅스 고유 타입 (u_int32_t 등)
#include <linux/netfilter.h>        // Netfilter 상수들 (NF_ACCEPT, NF_DROP 등)
#include <string.h>                 // 문자열 함수 (strcmp, strcasestr, sscanf 등)
#include <errno.h>                  // 에러 번호 처리

#include <libnetfilter_queue/libnetfilter_queue.h>  // Netfilter Queue 라이브러리 헤더

// 차단할 유해 사이트 도메인명 지정
#define BLOCK_HOST "gilgil.net"

// 디버깅용 패킷 HEX 덤프
void dump(unsigned char* buf, int size) {
    for (int i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n"); // 16바이트마다 줄 바꿈
        printf("%02X ", buf[i]); // 16진수 2자리 출력
    }
    printf("\n");
}

// 유해 사이트 검사
int is_malicious(unsigned char *data, int size) {
    // IP 헤더 최소 길이 20바이트 이상인지 확인
    if (size < 20) return 0;

    // IP 헤더 길이 계산 (하위 4비트는 IP 헤더 길이(4바이트 단위))
    int ip_header_len = (data[0] & 0x0F) * 4;
    // IP 헤더 + TCP 헤더 최소 20바이트 확인
    if (size < ip_header_len + 20) return 0;

    // TCP 헤더 길이 계산 (상위 4비트는 TCP 헤더 길이(4바이트 단위))
    int tcp_header_len = ((data[ip_header_len + 12] & 0xF0) >> 4) * 4;

    // HTTP 데이터 시작 위치 = IP 헤더 길이 + TCP 헤더 길이
    int http_offset = ip_header_len + tcp_header_len;

    // HTTP 데이터가 없으면 종료
    if (size <= http_offset) return 0;

    unsigned char *http = data + http_offset;       // HTTP 페이로드 시작 위치
    int http_size = size - http_offset;             // HTTP 데이터 크기

    // HTTP 데이터 내에서 "Host: " 문자열 찾기 (대소문자 무시)
    char *host_header = strcasestr((const char *)http, "Host: ");
    if (host_header) {
        char host[256] = {0};
        // Host: 다음에 나오는 도메인 문자열을 추출 (최대 255자)
        sscanf(host_header, "Host: %255s", host);

        // 문자열 내 개행 문자 제거 (줄 끝 등 제거용)
        host[strcspn(host, "\r\n")] = '\0';

        // 현재 확인된 호스트명 출력
        printf("[+] Host: %s\n", host);

        // 차단 대상 호스트명과 비교
        if (strcmp(host, BLOCK_HOST) == 0) {
            printf("[!] Blocked site detected: %s\n", host);
            return 1;   // 유해 사이트임을 알림
        }
    }

    return 0;   // 유해 사이트 아님
}

// Netfilter Queue에서 패킷이 들어올 때 호출되는 콜백 함수
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    unsigned char *packet_data;
    // 패킷 페이로드를 packet_data 포인터로 받고 길이 반환
    int len = nfq_get_payload(nfa, &packet_data);
    uint32_t id = 0;

    // 패킷 헤더에서 패킷 ID를 가져옴
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);

    // 페이로드가 존재하면 유해 사이트 검사 수행
    if (len >= 0) {
        if (is_malicious(packet_data, len)) {
            // 유해 사이트인 경우 패킷 드롭 (차단)
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
    }

    // 정상 패킷은 그대로 ACCEPT (통과)
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h; // netfilter 큐 핸들
    struct nfq_q_handle *qh;// 큐 핸들
    int fd; // 소켓 파일 디스크립터
    int rv;
    char buf[4096] __attribute__ ((aligned)); // 패킷 수신 버퍼 (정렬 필요)
    //CPU가 메모리를 올바르게 효율적으로 접근하도록 보장하기 위해

    // iptables 명령어로 INPUT과 OUTPUT 체인에 NFQUEUE 룰 삽입
    // 이로써 모든 송수신 패킷이 큐 번호 0으로 전달됨
    system("sudo iptables -I INPUT -j NFQUEUE --queue-num 0");
    system("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0");

    printf("[*] Opening NFQUEUE handle...\n");
    // NFQUEUE 라이브러리 핸들 열기
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "[-] Error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "[-] Error during nfq_unbind_pf()\n");
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "[-] Error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "[-] Error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "[-] Can't set packet_copy mode\n");
        exit(1);
    }

    printf("[*] Waiting for packets...\n");

    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
