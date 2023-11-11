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
#include "iprlib.h"

#define TIMEOUT (48000 * HZ)              /* 800 minute FORMAT UNIT default timeout */
#define BS 512                            /* Default blocksize */
#define SCSI_OFF sizeof(struct sg_header) /* offset to SCSI command data */
#define IOCTL_BUFFER_SIZE 512

int main(int argc, char **argv)
{
    /* Gather parameters */
    unsigned short int bs = BS;
    int timeout = TIMEOUT;
    int sg_fd;
    int i;
    int ok;
    int buf;
    char sbuf[256];
    char *file_name = NULL;
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
        strcat(sbuf,
               " [-b<Blocksize in Byte>] [-t<Timeout in Minutes>] <sg_device>'\n\n");
        fprintf(stderr, sbuf);
        exit(1);
    }
    /* Open device file */
    printf("Open device file ...\n");
    fflush(stdout);
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
    printf("   Done.\n");
    printf("   Done.\n");
    /* Issue mode select to change block size */
    uint8_t num_devs = 0;
    struct devs_to_init_t *cur_dev_init;
    int rc = 0;
    struct ipr_query_res_state res_state;
    uint8_t ioctl_buffer[IOCTL_BUFFER_SIZE];
    struct ipr_mode_parm_hdr *mode_parm_hdr;
    struct ipr_block_desc *block_desc;
    struct scsi_dev_data *scsi_dev_data;
    struct ipr_ioa *ioa;
    int status;
    int opens;
    uint8_t failure = 0;
    int max_y, max_x;
    uint8_t length;

    mode_parm_hdr = (struct ipr_mode_parm_hdr *)ioctl_buffer;
    memset(ioctl_buffer, 0, 255);

    mode_parm_hdr->block_desc_len = sizeof(struct ipr_block_desc);
    block_desc = (struct ipr_block_desc *)(mode_parm_hdr + 1);

    /* Setup block size */
    block_desc->block_length[0] = 0x00;
    block_desc->block_length[1] = BS >> 8;
    block_desc->block_length[2] = BS & 0xff;

    rc = ipr_mode_select(sg_fd, ioctl_buffer, sizeof(struct ipr_block_desc) + sizeof(struct ipr_mode_parm_hdr));

    rc = ipr_format_unit(sg_fd);
    /* unbind device
            if (ipr_jbod_sysfs_bind(dev,
                        IPR_JBOD_SYSFS_UNBIND))
                syslog(LOG_ERR, "Could not unbind %s: %m\n",
                       dev->dev_name); */
}