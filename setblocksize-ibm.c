/*
********************************************************************************
Header


********************************************************************************
*/

/*
********************************************************************************
* Include files
********************************************************************************
*/

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/param.h>
#include <scsi/scsi.h>
#include <scsi/sg.h>
#include "include/sg_err.h"
#include <stdint.h>

#define TIMEOUT (48000 * HZ)              /* 800 minute FORMAT UNIT default timeout */
#define BS 512                            /* Default blocksize */
#define SCSI_OFF sizeof(struct sg_header) /* offset to SCSI command data */
#define INQUIRY_VENDOR 8

static unsigned char cmd[SCSI_OFF + 18]; /* SCSI command buffer */

const char NAME[] = "setblocksize";
const char VER[] = "V0.2";

static void print_buf(const unsigned char *buf, size_t buf_len)
{
    size_t i = 0;
    for (i = 0; i < buf_len; ++i)
        fprintf(stdout, "%02X%s", buf[i],
                (i + 1) % 16 == 0 ? "\r\n" : " ");
}

/* process a complete scsi cmd. Use the generic scsi interface. */
static int handle_scsi_cmd(unsigned cmd_len,      /* command length */
                           unsigned in_size,      /* input data size */
                           unsigned char *i_buff, /* input buffer */
                           unsigned out_size,     /* output data size */
                           unsigned char *o_buff, /* output buffer */
                           int fd                 /* scsi fd */
)
{
    int status = 0;
    struct sg_header *sg_hd;

    /* safety checks */
    if (!cmd_len)
        return -1; /* need a cmd_len != 0 */
    if (!i_buff)
        return -1; /* need an input buffer != NULL */
#ifdef SG_BIG_BUFF
    if (SCSI_OFF + cmd_len + in_size > SG_BIG_BUFF)
        return -1;
    if (SCSI_OFF + out_size > SG_BIG_BUFF)
        return -1;
#else
    if (SCSI_OFF + cmd_len + in_size > 4096)
        return -1;
    if (SCSI_OFF + out_size > 4096)
        return -1;
#endif

    if (!o_buff)
        out_size = 0;

    /* generic scsi device header construction */
    sg_hd = (struct sg_header *)i_buff;
    sg_hd->reply_len = SCSI_OFF + out_size;
    sg_hd->twelve_byte = cmd_len == 12;
    sg_hd->result = 0;
#if 0
    sg_hd->pack_len    = SCSI_OFF + cmd_len + in_size; /* not necessary */
    sg_hd->pack_id;     /* not used */
    sg_hd->other_flags; /* not used */
#endif

    /* send command */
    status = write(fd, i_buff, SCSI_OFF + cmd_len + in_size);
    if (status < 0 || status != SCSI_OFF + cmd_len + in_size ||
        sg_hd->result)
    {
        /* some error happened */
        fprintf(stderr, "write(generic) result = 0x%x cmd = 0x%x\n",
                sg_hd->result, i_buff[SCSI_OFF]);
        perror("");
        return status;
    }

    if (!o_buff)
        o_buff = i_buff; /* buffer pointer check */

    /* retrieve result */
    status = read(fd, o_buff, SCSI_OFF + out_size);
    if (status < 0 || status != SCSI_OFF + out_size || sg_hd->result)
    {
        /* some error happened */
        fprintf(stderr, "read(generic) result = 0x%x cmd = 0x%x\n",
                sg_hd->result, o_buff[SCSI_OFF]);
        fprintf(stderr, "read(generic) sense "
                        "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
                sg_hd->sense_buffer[0], sg_hd->sense_buffer[1],
                sg_hd->sense_buffer[2], sg_hd->sense_buffer[3],
                sg_hd->sense_buffer[4], sg_hd->sense_buffer[5],
                sg_hd->sense_buffer[6], sg_hd->sense_buffer[7],
                sg_hd->sense_buffer[8], sg_hd->sense_buffer[9],
                sg_hd->sense_buffer[10], sg_hd->sense_buffer[11],
                sg_hd->sense_buffer[12], sg_hd->sense_buffer[13],
                sg_hd->sense_buffer[14], sg_hd->sense_buffer[15]);
        if (status < 0)
            perror("");
    }
    /* Look if we got what we expected to get */
    if (status == SCSI_OFF + out_size)
        status = 0; /* got them all */

    return status; /* 0 means no error */
}

#define INQUIRY_CMD 0x12
#define INQUIRY_CMDLEN 6
#define INQUIRY_REPLY_LEN 96
#define INQUIRY_VENDOR 8 /* Offset in reply data to vendor name */

/* request vendor brand and model */
static unsigned char *Inquiry(int fd /* scsi fd*/)
{
    unsigned char Inqbuffer[SCSI_OFF + INQUIRY_REPLY_LEN];
    unsigned char cmdblk[INQUIRY_CMDLEN] =
        {INQUIRY_CMD,       /* command */
         0,                 /* lun/reserved */
         0,                 /* page code */
         0,                 /* reserved */
         INQUIRY_REPLY_LEN, /* allocation length */
         0};                /* reserved/flag/link */

    memcpy(cmd + SCSI_OFF, cmdblk, sizeof(cmdblk));

    /*
     * +------------------+
     * | struct sg_header | <- cmd
     * +------------------+
     * | copy of cmdblk   | <- cmd + SCSI_OFF
     * +------------------+
     */

    if (handle_scsi_cmd(sizeof(cmdblk), 0, cmd,
                        sizeof(Inqbuffer) - SCSI_OFF, Inqbuffer, fd))
    {
        fprintf(stderr, "Inquiry failed\n");
        exit(2);
    }
    return (Inqbuffer + SCSI_OFF);
}

int main(int argc, char **argv)
{
    unsigned short int bs = BS;
    int timeout = TIMEOUT;
    int sg_fd;
    int i;
    int ok;
    int buf;
    char sbuf[256];
    char *file_name = NULL;
    unsigned char scsi_buf[65536];
    uint8_t ioctl_buffer[512];
    struct ipr_mode_parm_hdr *mode_parm_hdr;
    struct ipr_block_desc *block_desc;
    struct sg_header *sghp = (struct sg_header *)scsi_buf;
    Sg_scsi_id device;

    /* Print info */
    sprintf(sbuf, "\n");
    strcat(sbuf, NAME);
    strcat(sbuf, " ");
    strcat(sbuf, VER);
    strcat(sbuf, "\n\n");
    printf(sbuf);

    /* Check parameters */
    printf("Checking parameters ...\n");
    for (i = 1; i < argc; i++)
    {
        if (*argv[i] == '-')
        {
            if (!strncmp(argv[i], "-b", 2))
            {
                /* Use specified blocksize */
                printf("   Blocksize specified.\n");
                ok = sscanf(argv[i], "-b%d", &buf);
                bs = (unsigned short int)buf;
                if (ok != 1)
                    break;
            }
            else if (!strncmp(argv[i], "-t", 2))
            {
                /* Use specified timeout */
                printf("   Timeout specified.\n");
                ok = sscanf(argv[i], "-t%d", &buf);
                if ((buf < 1) || (buf > 1800))
                    break;
                timeout = buf * 60 * HZ;
                if (ok != 1)
                    break;
            }
            else
            {
                printf("   Unknown parameter: %s\n", argv[i]);
                file_name = 0;
                break;
            }
        }
        else
        {
            if (file_name == NULL)
                file_name = argv[i];
            else
            {
                printf("   Parameter error\n");
                file_name = 0;
                break;
            }
        }
    }
    if (file_name == NULL)
    {
        /* Parameter error, print help message */
        fprintf(stderr, "   Parameter error!\n");
        sprintf(sbuf, "   Usage: '");
        strcat(sbuf, NAME);
        strcat(sbuf,
               " [-b<Blocksize in Byte>] [-t<Timeout in Minutes>] <sg_device>'\n\n");
        fprintf(stderr, sbuf);
        exit(1);
    }
    printf("   Done.\n");
    if ((sg_fd = open(file_name, O_RDWR | O_EXCL)) < 0)
    {
        fprintf(stderr, "   File open error! (root permissions?)\n\n");
        exit(1);
    }
    /* Just to be safe, check we have a sg device by trying an ioctl */
    if (ioctl(sg_fd, SG_GET_TIMEOUT, NULL) < 0)
    {
        fprintf(stderr, "   File open error!\n");
        fprintf(stderr, "   '%s' doesn't seem to be a sg device\n\n", file_name);
        close(sg_fd);
        exit(1);
    }
    printf("%s\n", Inquiry(sg_fd) + INQUIRY_VENDOR);
}