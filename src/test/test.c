/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file test.c
 *  @author Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *  @date 2020-05-22
 *  
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 *  Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */
#include "test.h"

#define EVENTCOUNT 10
#define EVENTBACK 1
#define EVENTSIZE 160
#define EVENTNAMESIZE 8
#define EVENTNAMESIZEALLOC (EVENTNAMESIZE+1)

typedef struct TestConf {
    int ecount;
    int esize;
    int eback;
    int port;
#ifdef PTHREADFOUND
    int tcount;
#endif
    char *producer;
    char *host;
    int flag;
} TestConf;

void printUsage(char *runString) {
    printf("Usage: %s [Options]\n", runString);
    printf("Options:\n");
    printf("  -m\t\tUse the MultiRecord.\n");
    printf("  -d\t\tSet Flag that the service does not handle duplicates.\n");
    printf("  -i STRING\tSet interpeter/producer. default: TEST\n");
    printf("  -h STRING\tHost to connect. default: localhost\n");
    printf("  -p PORT\tPort the service runs on. default: 5001\n");
    printf("  -c COUNT\tCount of generated messages. default: %d\n", EVENTCOUNT);
    printf("  -s SIZE\tSize of generated messages. default: %d\n", EVENTSIZE);
    printf("  -b COUNT\tCount of recevied messages. Has to be c%%b=0. default: %d\n", EVENTBACK);
#ifdef PTHREADFOUND
    printf("  -t COUNT\tCount of threads. default: %d\n", 0);
#endif
}

void parseConf(int argc, char *argv[], TestConf *conf) {
    conf->ecount = EVENTCOUNT;
    conf->esize = EVENTSIZE;
    conf->eback = EVENTBACK;
    conf->producer = "TEST";
    conf->host = "localhost";
    conf->port = 5001;
#ifdef PTHREADFOUND
    conf->tcount = 0;
#endif
    conf->flag = 0;
    int opt;
#ifdef PTHREADFOUND
    while ((opt = getopt(argc, argv, "mdp:i:h:c:s:b:t:")) != -1) {
#else
    while ((opt = getopt(argc, argv, "mdp:i:h:c:s:b:")) != -1) {
#endif
        switch (opt) {
            case 'm':
                conf->flag = conf->flag | LOG_MULTIPLE_RECORDS_AS_ONE;
                break;
            case 'd':
                conf->flag = conf->flag | DO_NOT_HANDLE_DUPLICATES;
                break;
            case 'i':
                conf->producer = optarg;
                break;
            case 'h':
                conf->host = optarg;
                break;
            case 'p':
                conf->port = atoi(optarg);
                break;
            case 'c':
                conf->ecount = atoi(optarg);
                break;
            case 's':
                conf->ecount = atoi(optarg);
                break;
            case 'b':
                conf->eback = atoi(optarg);
                break;
#ifdef PTHREADFOUND
            case 't':
                conf->tcount = atoi(optarg);
                break;
#endif
            default: /* '?' */
                printUsage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (conf->ecount % conf->eback != 0) {
        printf("c%%b is not 0.\n");
        exit(EXIT_FAILURE);
    }
}

void *threadStart(void *conf) {
    TestConf *tconf = (TestConf *) conf;
    struct timespec start, end;
    double cpu_time_used;
    uint16_t alg_ids[4] = {TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA512};
    uiimctx ctx;
    char **eventnames = calloc(tconf->ecount, sizeof (char*));
    char **eventdata = calloc(tconf->ecount, sizeof (char*));
    for (int i = 0; i < tconf->ecount; i++) {
        eventnames[i] = rand_string_alloc(EVENTNAMESIZE);
        eventdata[i] = rand_string_alloc(tconf->esize);
    }
    printf("Random entries generated. Start time measurent\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    uiim_init(&ctx, 16, tconf->producer, tconf->host, tconf->port, tconf->flag);
    for (int i = 0; i < 4; i++) {
        uiim_add_alg_id(&ctx, alg_ids[i]);
    }

    for (int i = 0; i < tconf->ecount; i++) {
        uiim_add_event(&ctx, rand_string_alloc(8), rand_string_alloc(tconf->esize), tconf->esize);
    }

    for (int i = 0; i < tconf->ecount / tconf->eback; i++) {
        Answer *replies = uiim_finish_all(&ctx, tconf->eback);
        for (int j = 0; j < tconf->eback; j++) {
            //printf("SeqNum: %u, RC: %d\n", replies[j].seqNum, replies[j].rc);
        }

    }
    uiim_free_ctx(&ctx);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_taken; 
    time_taken = (end.tv_sec - start.tv_sec) * 1e9; 
    time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9;
    printf("%f, in sec\n", time_taken);
}

int main(int argc, char *argv[]) {
    TestConf conf;
    parseConf(argc, argv, &conf);
#ifdef PTHREADFOUND
    if (conf.tcount == 0) {
        threadStart(&conf);
    } else {
        pthread_t threads[conf.tcount];
        for (int i = 0; i < conf.tcount; i++) {
            pthread_create(&threads[i], NULL, threadStart, &conf);
        }
        for (int i = 0; i < conf.tcount; i++) {
            pthread_join(threads[i], NULL);
        }
    }
#else
    threadStart(&conf);
#endif

}