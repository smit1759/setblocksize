/*
********************************************************************************
Header

Project:        setblocksize

This file:      setblocksize.c
Version:        V0.2

Description:    Reformat SCSI disk with specified block size
                Thanks to Seagate for providing protocol information

      Return value:  0 on success, 1 on error

Copyright:      (C) 2003 by Michael Baeuerle
License:        GPL V2 or any later version

Language:       C
Style rules:    -

Written for:    Platform:       all
                OS:             GNU/Linux
Tested with:    Compiler:       gcc (Version: 2.91.66)
                Platform:       IA32 (Pentium)
                OS:             GNU/Linux (Kernel version: 2.2.10)
Tested with:    Compiler:       gcc (Version: 2.96.1)
                Platform:       IA32 (Pentium2)
                OS:             GNU/Linux (Kernel version: 2.4.21)
Tested with:    Compiler:       gcc (Version: 3.3.6)
                Platform:       IA32 (PentiumPro)
                OS:             GNU/Linux (Kernel version: 2.6.16.20)
Do not work:    Platform:       non GNU/Linux

Created:        2003-03-22 by Michael Baeuerle
Last mod.:      2007-09-04 by Michael Baeuerle

Changelog:

V0.0            Initial version (Inspired by sg-utils)
                LUN and blocksize must be specified at compile time

V0.1            Print manufacturer and model name of selected device and
                 ask if this is the desired device (using INQUIRY command)
                LUN selection removed: ID and LUN are implicit specified with
       the sg device (The LUN value of V0.0 was ignored)
                Also print ID, LUN, Host and channel numbers
      Check for device type supports the FORMAT UNIT command

V0.2            The new blocksize can now be specified on command line
                The program now aborts if a SCSI command reports CHECK CONDITION
                The timeout can now be specified on the command line


To do:          -
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
#include <linux/types.h>
#include <syslog.h>
#include <scsi/sg.h>
/*
********************************************************************************
* Global constants
********************************************************************************
*/

#define TIMEOUT (48000 * HZ) /* 800 minute FORMAT UNIT default timeout */
#define BS 512               /* Default blocksize */
#define IPR_CCB_CDB_LEN 16
#define IPR_MAX_XFER 0x8000
#define IPR_S_G_BUFF_ALIGNMENT 512
#define IPR_DEFECT_LIST_HDR_LEN 4
#define FORMAT_UNIT 0x04
#define IPR_FORMAT_DATA 0x10
#define IPR_FORMAT_IMMED 2
#define IPR_INTERNAL_TIMEOUT (30)         /* 30 seconds */
#define IPR_INTERNAL_DEV_TIMEOUT (2 * 60) /* 2 minutes */
#define IPR_JBOD_SYSFS_UNBIND 0
#define IPR_JBOD_SYSFS_BIND 1
#define IPR_MODE_SENSE_LENGTH 255
#define IPR_SET_MODE(change_mask, cur_val, new_val) \
   {                                                \
      int mod_bits = (cur_val ^ new_val);           \
      if ((change_mask & mod_bits) == mod_bits)     \
      {                                             \
         cur_val = new_val;                         \
      }                                             \
   }
#define scsi_log(level, dev, fmt)         \
   do                                     \
   {                                      \
      syslog(level, "%d:%d:%d:%d: " fmt); \
   } while (0)

#define scsi_info(dev, fmt) \
   scsi_log(LOG_NOTICE, dev, fmt)

#define scsi_err(dev, fmt, ...) \
   scsi_log(LOG_ERR, dev, fmt)

#define scsi_warn(dev, fmt, ...) \
   scsi_log(LOG_WARNING, dev, fmt)

#define scsi_cmd_err(dev, sense, cmd, rc)                              \
   printf("%s failed. rc=%d, SK: %X ASC: %X ASCQ: %X\n",               \
          cmd, rc, (sense)->sense_key & 0x0f, (sense)->add_sense_code, \
          (sense)->add_sense_code_qual);

const char NAME[] = "setblocksize";
const char VER[] = "V0.2";
const int cdb_size[] = {6, 10, 10, 0, 16, 12, 16, 16};
/*
********************************************************************************
* Main function
********************************************************************************
*/
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct ipr_block_desc
{
   uint8_t num_blocks[4];
   uint8_t density_code;
   uint8_t block_length[3];
};
struct ipr_mode_parm_hdr
{
   uint8_t length;
   uint8_t medium_type;
   uint8_t device_spec_parms;
   uint8_t block_desc_len;
};

struct sense_data_t
{
   uint8_t error_code;
   uint8_t segment_numb;
   uint8_t sense_key;
   uint8_t info[4];
   uint8_t add_sense_len;
   uint8_t cmd_spec_info[4];
   uint8_t add_sense_code;
   uint8_t add_sense_code_qual;
   uint8_t field_rep_unit_code;
   uint8_t sense_key_spec[3];
   uint8_t add_sense_bytes[0];
};

struct df_sense_data_t
{
   uint8_t error_code;
   uint8_t sense_key;
   uint8_t add_sense_code;
   uint8_t add_sense_code_qual;
   uint8_t rfield;
   uint8_t rsrvd[2];
   uint8_t add_sense_len;
};

struct ipr_mode_page_hdr
{
   u8 page_code : 6;
   u8 reserved1 : 1;
   u8 parms_saveable : 1;
   u8 page_length;
};
struct ipr_control_mode_page
{
   /* Mode page 0x0A */
   struct ipr_mode_page_hdr hdr;
   u8 rlec : 1;
   u8 gltsd : 1;
   u8 reserved1 : 3;
   u8 tst : 3;
   u8 dque : 1;
   u8 qerr : 2;
   u8 reserved2 : 1;
   u8 queue_algorithm_modifier : 4;
   u8 eaerp : 1;
   u8 uaaerp : 1;
   u8 raerp : 1;
   u8 swp : 1;
   u8 reserved4 : 2;
   u8 rac : 1;
   u8 reserved3 : 1;
   u8 autoload_mode : 3;
   u8 reserved5 : 3;
   u8 tas : 1;
   u8 ato : 1;
   u16 ready_aen_holdoff_period;
   u16 busy_timeout_period;
   u16 reserved6;
};

static void print_buf(const unsigned char *buf, size_t buf_len)
{
   size_t i = 0;
   for (i = 0; i < buf_len; ++i)
      fprintf(stdout, "%02X%s", buf[i],
              (i + 1) % 16 == 0 ? "\r\n" : " ");
}

static int _sg_ioctl(int fd, uint8_t cdb[IPR_CCB_CDB_LEN],
                     void *dxferp, uint32_t xfer_len, uint32_t data_direction,
                     struct sense_data_t *sense_data,
                     uint32_t timeout_in_sec, int retries)
{
   int rc = 0;
   sg_io_hdr_t io_hdr_t;
   sg_iovec_t *iovec = NULL;
   int iovec_count = 0;
   int i;
   int buff_len, segment_size;
   uint8_t *buf;
   struct sense_data_t sd;
   struct df_sense_data_t *dfsdp = NULL;

   for (i = 0; i < (retries + 1); i++)
   {
      // printf("Data& %p, Data: %p\n", &data, data);
      // print_buf(data, sizeof(data));
      printf("\n");
      memset(&io_hdr_t, 0, sizeof(io_hdr_t));
      memset(&sd, 0, sizeof(struct sense_data_t));
      io_hdr_t.interface_id = 'S';
      io_hdr_t.cmd_len = cdb_size[(cdb[0] >> 5) & 0x7];
      io_hdr_t.iovec_count = iovec_count;
      io_hdr_t.flags = 0;
      io_hdr_t.pack_id = 0;
      io_hdr_t.usr_ptr = 0;
      io_hdr_t.sbp = (unsigned char *)&sd;
      io_hdr_t.mx_sb_len = sizeof(struct sense_data_t);
      io_hdr_t.timeout = timeout_in_sec * 1000;
      io_hdr_t.cmdp = cdb;
      io_hdr_t.dxfer_direction = data_direction;
      io_hdr_t.dxfer_len = xfer_len;
      io_hdr_t.dxferp = dxferp;
      printf("Header: \n");
      print_buf(&io_hdr_t, sizeof(io_hdr_t));
      printf("\n");

      rc = ioctl(fd, SG_IO, &io_hdr_t);

      if (rc == -1 && errno == EINVAL)
      {
         rc = -EINVAL;
         goto out;
      }

      if (rc == 0 && io_hdr_t.masked_status == CHECK_CONDITION)
         rc = CHECK_CONDITION;
      else if (rc == 0 && (io_hdr_t.host_status || io_hdr_t.driver_status))
         rc = -EIO;

      if (rc == 0 || io_hdr_t.host_status == 1)
         break;
   }

   memset(sense_data, 0, sizeof(struct sense_data_t));

   if (((sd.error_code & 0x7F) == 0x72) || ((sd.error_code & 0x7F) == 0x73))
   {
      dfsdp = (struct df_sense_data_t *)&sd;
      /* change error_codes 0x72 to 0x70 and 0x73 to 0x71 */
      sense_data->error_code = dfsdp->error_code & 0xFD;

      /* Do not change the order of the next two assignments
       * In the same uint8_t, the 4th bit of fixed format corresponds
       * to SDAT_OVLF and the last 4 bits to sense_key.
       */
      sense_data->sense_key = dfsdp->sense_key & 0x0F;
      if (dfsdp->rfield & 0x80)
         sense_data->sense_key |= 0x10;

      /* copy the other values */
      sense_data->add_sense_code = dfsdp->add_sense_code;
      sense_data->add_sense_code_qual = dfsdp->add_sense_code_qual;
      sense_data->add_sense_len = 0;
   }
   else if (sd.error_code & 0x7F)
   {
      memcpy(sense_data, &sd, sizeof(struct sense_data_t));
   }

out:
   if (iovec_count)
   {
      for (i = 0, buf = (uint8_t *)dxferp; i < iovec_count; i++)
      {
         if (data_direction == SG_DXFER_FROM_DEV)
            memcpy(buf, iovec[i].iov_base, iovec[i].iov_len);
         buf += iovec[i].iov_len;
         free(iovec[i].iov_base);
      }
      free(iovec);
   }

   return rc;
};

/**
 * sg_ioctl -
 * @fd: 		file descriptor
 * @cdb:        	cdb
 * @data:		data pointer
 * @xfer_len            transfer length
 * @data_direction      transfer to dev or from dev
 * @sense_data          sense data pointer
 * @timeout_in_sec      timeout value
 *
 * Returns:
 *   0 if success / non-zero on failure
 **/
int sg_ioctl(int fd, u8 cdb[IPR_CCB_CDB_LEN],
             void *data, u32 xfer_len, u32 data_direction,
             struct sense_data_t *sense_data,
             u32 timeout_in_sec)
{
   return _sg_ioctl(fd, cdb,
                    data, xfer_len, data_direction,
                    sense_data, timeout_in_sec, 0);
};

int ipr_mode_select(int fd, void *buff, int length)
{
   u8 cdb[IPR_CCB_CDB_LEN];
   struct sense_data_t sense_data;
   int rc;
   memset(cdb, 0, IPR_CCB_CDB_LEN);

   cdb[0] = MODE_SELECT;
   cdb[1] = 0x10; /* PF = 1, SP = 0 */
   cdb[4] = length;

   rc = sg_ioctl(fd, cdb, buff,
                 length, SG_DXFER_TO_DEV,
                 &sense_data, IPR_INTERNAL_TIMEOUT);

   if (rc != 0)
      scsi_cmd_err(dev, &sense_data, "Mode Select", rc);
   return rc;
}

/**
 * mode_sense -
 * @dev:		ipr dev struct
 * @page:		page number
 * @buff:		buffer
 * @sense_data		sense_data_t struct
 *
 * Returns:
 *   0 if success / non-zero on failure
 **/
static int mode_sense(int fd, u8 page, void *buff,
                      struct sense_data_t *sense_data)
{
   u8 cdb[IPR_CCB_CDB_LEN];
   int rc;
   u8 length = IPR_MODE_SENSE_LENGTH; /* xxx FIXME? */

   memset(cdb, 0, IPR_CCB_CDB_LEN);

   cdb[0] = MODE_SENSE;
   cdb[2] = page;
   cdb[4] = length;

   rc = sg_ioctl(fd, cdb, buff,
                 length, SG_DXFER_FROM_DEV,
                 sense_data, IPR_INTERNAL_DEV_TIMEOUT);
   return rc;
}

/**
 * ipr_mod_sense - issue a mode sense command
 * @dev:		ipr dev struct
 * @page:       	mode page
 * @buff:		data buffer
 *
 * Returns:
 *   0 if success / non-zero on failure
 **/
int ipr_mode_sense(int fd, u8 page, void *buff)
{
   struct sense_data_t sense_data;
   int rc;

   memset(&sense_data, 0, sizeof(sense_data));
   rc = mode_sense(fd, page, buff, &sense_data);

   /* post log if error unless error is device format in progress */
   if ((rc != 0) && (rc != ENOENT) &&
       (((sense_data.error_code & 0x7F) != 0x70) ||
        ((sense_data.sense_key & 0x0F) != 0x02) || /* NOT READY */
        (sense_data.add_sense_code != 0x04) ||     /* LOGICAL UNIT NOT READY */
        (sense_data.add_sense_code_qual != 0x04))) /* FORMAT IN PROGRESS */
      scsi_cmd_err(dev, &sense_data, "Mode Sense", rc);

   return rc;
}
/**
 * ipr_disable_qerr -
 * @dev:		ipr dev struct
 *
 * Returns:
 *   0 if success / non-zero on failure
 **/
int ipr_disable_qerr(int fd)
{
   u8 ioctl_buffer[512];
   u8 ioctl_buffer2[512];
   struct ipr_control_mode_page *control_mode_page;
   struct ipr_control_mode_page *control_mode_page_changeable;
   struct ipr_mode_parm_hdr *mode_parm_hdr;
   int status;
   u8 length;

   /* Issue mode sense to get the control mode page */
   status = ipr_mode_sense(fd, 0x0a, &ioctl_buffer);

   if (status)
      return -EIO;

   /* Issue mode sense to get the control mode page */
   status = ipr_mode_sense(fd, 0x4a, &ioctl_buffer2);

   if (status)
      return -EIO;

   mode_parm_hdr = (struct ipr_mode_parm_hdr *)ioctl_buffer2;

   control_mode_page_changeable = (struct ipr_control_mode_page *)(((u8 *)(mode_parm_hdr + 1)) + mode_parm_hdr->block_desc_len);

   mode_parm_hdr = (struct ipr_mode_parm_hdr *)ioctl_buffer;

   control_mode_page = (struct ipr_control_mode_page *)(((u8 *)(mode_parm_hdr + 1)) + mode_parm_hdr->block_desc_len);

   /* Turn off QERR since some drives do not like QERR
    and IMMED bit at the same time. */
   IPR_SET_MODE(control_mode_page_changeable->qerr,
                control_mode_page->qerr, 0);

   /* Issue mode select to set page x0A */
   length = mode_parm_hdr->length + 1;

   mode_parm_hdr->length = 0;
   control_mode_page->hdr.parms_saveable = 0;
   mode_parm_hdr->medium_type = 0;
   mode_parm_hdr->device_spec_parms = 0;

   status = ipr_mode_select(fd, &ioctl_buffer, length);

   if (status)
      return -EIO;

   return 0;
}

/**
 * ipr_format_unit -
 * @dev:		ipr dev struct
 *
 * Returns:
 *   0 if success / non-zero on failure
 **/
int ipr_format_unit(int fd)
{
   int rc;
   u8 cdb[IPR_CCB_CDB_LEN];
   struct sense_data_t sense_data;
   u8 *defect_list_hdr;
   int length = IPR_DEFECT_LIST_HDR_LEN;

   memset(cdb, 0, IPR_CCB_CDB_LEN);

   defect_list_hdr = calloc(1, IPR_DEFECT_LIST_HDR_LEN);

   cdb[0] = FORMAT_UNIT;
   cdb[1] = IPR_FORMAT_DATA; /* lun = 0, fmtdata = 1, cmplst = 0, defect list format = 0 */

   defect_list_hdr[1] = IPR_FORMAT_IMMED; /* FOV = 0, DPRY = 0, DCRT = 0, STPF = 0, IP = 0, DSP = 0, Immed = 1, VS = 0 */

   rc = sg_ioctl(fd, cdb, defect_list_hdr,
                 length, SG_DXFER_TO_DEV,
                 &sense_data, IPR_INTERNAL_DEV_TIMEOUT);

   free(defect_list_hdr);
   if (rc != 0)
      scsi_cmd_err(dev, &sense_data, "Format Unit", rc);
   return rc;
}

int ipr_reset_device(int fd)
{
   int rc, arg;

   arg = SG_SCSI_RESET_DEVICE;
   rc = ioctl(fd, SG_SCSI_RESET, &arg);

   if (rc != 0)
      scsi_err(dev, "Reset Device failed. %m\n");

   return rc;
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
   struct sg_header *sghp = (struct sg_header *)scsi_buf;
   Sg_scsi_id device;
   /* INQUIRY command */
   unsigned char inquiry[6] = {0x12, 0x00, 0x00, 0x00, 0x20, 0x00};
   /* MODE SELECT command */
   unsigned char mode_select[6] = {0x15, 0x10, 0x00, 0x00, 0x0C, 0x00};
   /* FORMAT UNIT command */
   unsigned char format_unit[6] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00};
   /* Parameter list with block descriptor */
   // 00 00 00 08 00 00 00 00 00 00 02 00
   unsigned char para_list[12] = {0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   /* new block descriptor and params from iprconfig */

   /* end new logic*/
   int inquiry_data_len = sizeof(struct sg_header) + 0x06;
   int mode_select_data_len = sizeof(struct sg_header) + 0x06 + 0x0C;
   int format_unit_data_len = sizeof(struct sg_header) + 0x06;

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

   /* Set new block size */
   printf("New blocksize: %u Bytes\n", (unsigned int)bs);
   para_list[10] = (unsigned char)((bs & 0xFF00) >> 8);
   para_list[11] = (unsigned char)(bs & 0x00FF);

   /* Print timeout */
   printf("Format timeout: %d minutes\n", (timeout / 60) / HZ);

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

   /* Send INQUIRY command */
   printf("Prepare command ...\n");
   fflush(stdout);
   sghp->reply_len = sizeof(struct sg_header) + 0x20;
   sghp->pack_id = 0;
   sghp->twelve_byte = 0;
   memcpy(scsi_buf + sizeof(struct sg_header), inquiry, 0x06);
   printf("   Done.\n");
   printf("Send INQUIRY command ...\n");
   fflush(stdout);
   if (write(sg_fd, scsi_buf, inquiry_data_len) < 0)
   {
      fprintf(stderr, "   Write error\n\n");
      close(sg_fd);
      exit(1);
   }
   /* Read status (sense_buffer) */
   if (read(sg_fd, scsi_buf, sizeof(struct sg_header) + 0x20) < 0)
   {
      fprintf(stderr, "   Read error\n\n");
      close(sg_fd);
      exit(1);
   }
   printf("   Done.\n");
   /* Error processing */
   printf("Check status ...\n");
   fflush(stdout);
   if (sghp->pack_id != 0) /* This shouldn't happen */
      printf("   Inquiry pack_id mismatch: Wanted=%d, Got=%d\n!",
             0, sghp->pack_id);
   ok = 0;
   switch (sg_err_category(sghp->target_status, sghp->host_status,
                           sghp->driver_status, sghp->sense_buffer, SG_MAX_SENSE))
   {
   case SG_ERR_CAT_CLEAN:
      ok = 1;
      break;
   case SG_ERR_CAT_RECOVERED:
      printf("   Recovered error, continue\n");
      ok = 1;
      break;
   default:
      sg_chk_n_print("   Error", sghp->target_status,
                     sghp->host_status, sghp->driver_status,
                     sghp->sense_buffer, SG_MAX_SENSE);
      break;
   }
   if (ok)
      printf("   Command successful.\n");
   else
   {
      fprintf(stderr, "   Command NOT succesful!\n\n");
      close(sg_fd);
      exit(1);
   }

   /* Check for LUN to be valid */
   printf("Check for LUN ...\n");
   switch (scsi_buf[sizeof(struct sg_header)] >> 5)
   {
   case 0:
      printf("   LUN present.\n");
      break;
   case 1:
      fprintf(stderr, "   Error: LUN supported but not present!\n\n");
      close(sg_fd);
      exit(1);
   case 3:
      fprintf(stderr, "   Error: LUN not supported by this device!\n\n");
      close(sg_fd);
      exit(1);
   default:
      fprintf(stderr, "   Error: Cannot determine status of LUN!\n\n");
      close(sg_fd);
      exit(1);
   }
   if (ioctl(sg_fd, SG_GET_SCSI_ID, &device) < 0)
   {
      fprintf(stderr, "   Cannot determine ID & LUN numbers!\n");
      close(sg_fd);
      exit(1);
   }

   /* Print device name and ask for OK */
   printf("\n=================================================================\
==============\n");
   printf("SCSI ID     : %d\n", device.scsi_id);
   printf("LUN         : %d\n", device.lun);
   printf("Connected to: Host%d / Channel%d\n", device.host_no, device.channel);
   strncpy(sbuf, scsi_buf + sizeof(struct sg_header) + 0x08, 0x08);
   sbuf[0x08] = 0x00;
   printf("Manufacturer: %s\n", sbuf);
   strncpy(sbuf, scsi_buf + sizeof(struct sg_header) + 0x10, 0x10);
   sbuf[0x10] = 0x00;
   printf("Model       : %s\n", sbuf);
   ok = 0;
   switch (scsi_buf[sizeof(struct sg_header)] & 0x1F)
   {
   case 0:
      sprintf(sbuf, "Disk");
      ok = 1;
      break;
   case 1:
      sprintf(sbuf, "Tape");
      break;
   case 2:
      sprintf(sbuf, "Printer");
      break;
   case 3:
      sprintf(sbuf, "Processor");
      break;
   case 4:
      sprintf(sbuf, "WORM");
      break;
   case 5:
      sprintf(sbuf, "CDROM");
      break;
   case 6:
      sprintf(sbuf, "Scanner");
      break;
   case 7:
      sprintf(sbuf, "Optical disk");
      ok = 1;
      break;
   case 8:
      sprintf(sbuf, "Media changer");
      break;
   case 9:
      sprintf(sbuf, "Communication");
      break;
   case 12:
      sprintf(sbuf, "Storage array controller");
      break;
   default:
      sprintf(sbuf, "Unknown");
   }
   printf("Device type : %s\n", sbuf);
   printf("=================================================================\
==============\n");
   if (!ok)
   {
      fprintf(stderr, "This type of device do not support the FORMAT UNIT \
command!\n");
      printf("Exiting ...\n\n");
      close(sg_fd);
      exit(1);
   }
   printf("Do you really want to reformat this device [y/n]? ");
   fflush(stdout);
   fscanf(stdin, "%c", &sbuf[0]);
   printf("\n");
   if (sbuf[0] != 'y')
   {
      printf("Aborted.\n\nExiting ...\n\n");
      close(sg_fd);
      exit(1);
   }

   /* Send MODE SELECT command */
   printf("Prepare command ...\n");
   fflush(stdout);
   // sghp->reply_len = sizeof(struct sg_header);
   // sghp->pack_id = 0;
   // sghp->twelve_byte = 0;

   struct ipr_mode_parm_hdr *mode_parm_hdr;
   struct ipr_block_desc *block_desc;
   // prepare params
   uint8_t newSize = sizeof(struct ipr_block_desc) + sizeof(struct ipr_mode_parm_hdr);
   int rc;
   struct sense_data_t sense_data;
   uint8_t ioctl_buffer[512];
   uint8_t cdb[IPR_CCB_CDB_LEN];
   mode_parm_hdr = (struct ipr_mode_parm_hdr *)ioctl_buffer;
   memset(ioctl_buffer, 0, 255);
   mode_parm_hdr->block_desc_len = sizeof(struct ipr_block_desc);
   block_desc = (struct ipr_block_desc *)(mode_parm_hdr + 1);
   /* Setup block size */
   block_desc->block_length[0] = 0x00;
   block_desc->block_length[1] = bs >> 8;
   block_desc->block_length[2] = bs & 0xff;
   // memcpy(&ioctl_buffer, &mode_parm_hdr, sizeof(mode_parm_hdr));
   // memcpy(&ioctl_buffer + sizeof(mode_parm_hdr), &block_desc, sizeof(block_desc));

   memset(cdb, 0, IPR_CCB_CDB_LEN);

   cdb[0] = MODE_SELECT;
   cdb[1] = 0x10; /* PF = 1, SP = 0 */
   cdb[4] = sizeof(struct ipr_block_desc) + sizeof(struct ipr_mode_parm_hdr);
   printf("\nSend MODE SELECT command ...\n");
   ipr_disable_qerr(sg_fd);
   print_buf(ioctl_buffer, sizeof(ioctl_buffer));
   rc = ipr_mode_select(sg_fd, ioctl_buffer, sizeof(struct ipr_block_desc) + sizeof(struct ipr_mode_parm_hdr));
   if (rc != 0)
   {
      scsi_cmd_err("dev", &sense_data, "Mode Select", rc);
      rc = ipr_reset_device(sg_fd);
      close(sg_fd);
      exit(1);
   }
   // copy to our buffer
   // memcpy(scsi_buf + sizeof(struct sg_header), cdb, sizeof(cdb));
   // memcpy(scsi_buf + sizeof(struct sg_header) + sizeof(cdb), ioctl_buffer, sizeof(ioctl_buffer));

   printf("   Done.\n");
   fflush(stdout);
   // old: write(sg_fd, scsi_buf, mode_select_data_len)
   // sizeof(struct ipr_block_desc) + sizeof(struct ipr_mode_parm_hdr)
   /*
   if (write(sg_fd, scsi_buf, newSize) < 0)
   {
      fprintf(stderr, "   Write error\n\n");
      close(sg_fd);
      exit(1);
   }
   */
   /* Read status (sense_buffer)
   if (read(sg_fd, scsi_buf, sizeof(struct sg_header)) < 0)
   {
      fprintf(stderr, "   Read error\n\n");
      close(sg_fd);
      exit(1);
   }
   Error processing
   printf("Check status ...\n");
   fflush(stdout);
   if (sghp->pack_id != 0) /* This shouldn't happen
      printf("   Inquiry pack_id mismatch: Wanted=%d, Got=%d\n!",
             0, sghp->pack_id);
   ok = 0;
   switch (sg_err_category(sghp->target_status, sghp->host_status,
                           sghp->driver_status, sghp->sense_buffer, SG_MAX_SENSE))
   {
   case SG_ERR_CAT_CLEAN:
      ok = 1;
      break;
   case SG_ERR_CAT_RECOVERED:
      printf("   Recovered error, continue\n");
      ok = 1;
      break;
   default:
      sg_chk_n_print("   Error", sghp->target_status,
                     sghp->host_status, sghp->driver_status,
                     sghp->sense_buffer, SG_MAX_SENSE);
      break;
   }
   if (ok)
      printf("   Command successful.\n");
   else
   {
      fprintf(stderr, "   Command NOT succesful!\n\n");
      close(sg_fd);
      exit(1);
   }
*/
   /* Send FORMAT UNIT command */
   printf("Prepare command ...\n");
   fflush(stdout);
   /* sghp->reply_len = sizeof(struct sg_header);
     sghp->pack_id = 0;
     sghp->twelve_byte = 0;
     memcpy(scsi_buf + sizeof(struct sg_header), format_unit, 0x06);
     uint8_t cdb1[6];
     uint8_t *defect_list_hdr;
     struct sense_data_t sense_data1;
     int length = IPR_DEFECT_LIST_HDR_LEN;
     memset(cdb, 0, IPR_CCB_CDB_LEN);
     defect_list_hdr = calloc(1, IPR_DEFECT_LIST_HDR_LEN);
     cdb[0] = FORMAT_UNIT;
     cdb[1] = IPR_FORMAT_DATA;              lun = 0, fmtdata = 1, cmplst = 0, defect list format = 0
     defect_list_hdr[1] = IPR_FORMAT_IMMED;  FOV = 0, DPRY = 0, DCRT = 0, STPF = 0, IP = 0, DSP = 0, Immed = 1, VS = 0
     buf = timeout;
     printf("Send set timeout command ...\n");
     if (ioctl(sg_fd, SG_SET_TIMEOUT, &buf) < 0)
     {
        fprintf(stderr, "   Error!\n");
        fprintf(stderr, "   Cannot set timeout\n\n");
        close(sg_fd);
        exit(1);
     }*/

   printf("Send FORMAT UNIT command ...\n");
   // rc = _sg_ioctl(sg_fd, cdb1, defect_list_hdr,               length, SG_DXFER_TO_DEV,  &sense_data1, 120, 0);
   rc = ipr_format_unit(sg_fd);
   // free(defect_list_hdr);
   if (rc != 0)
   {
      scsi_cmd_err("dev", &sense_data, "Format Unit", rc);
      close(sg_fd);
      // printf("\n");
      // printf("    Failed. RC: %d\n", rc);
      // print_buf(&sense_data1, sizeof(sense_data1));
      // printf("\n");
      //  printf("    Sense error: %s", );
      exit(1);
   }
   /*
   printf("   Done.\n");
   printf("Send FORMAT UNIT command ...\n");
   fflush(stdout);
   if (write(sg_fd, scsi_buf, format_unit_data_len) < 0)
   {
      fprintf(stderr, "   Write error\n\n");
      close(sg_fd);
      exit(1);
   }

   printf("   *** Please wait - Do not manually interrupt or power down! ***\n");
   if (read(sg_fd, scsi_buf, sizeof(struct sg_header)) < 0)
   {
      fprintf(stderr, "   Read error\n\n");
      close(sg_fd);
      exit(1);
   }
   printf("   Done.\n");
   */
   /* Error processing */
   printf("Check status ... \n");
   if (sghp->pack_id != 0) /* This shouldn't happen */
      printf("   Inquiry pack_id mismatch: Wanted=%d, Got=%d\n!",
             0, sghp->pack_id);
   ok = 0;
   switch (sg_err_category(sghp->target_status, sghp->host_status,
                           sghp->driver_status, sghp->sense_buffer, SG_MAX_SENSE))
   {
   case SG_ERR_CAT_CLEAN:
      ok = 1;
      break;
   case SG_ERR_CAT_RECOVERED:
      printf("   Recovered error, continue\n");
      ok = 1;
      break;
   default:
      sg_chk_n_print("   Error", sghp->target_status,
                     sghp->host_status, sghp->driver_status,
                     sghp->sense_buffer, SG_MAX_SENSE);
      break;
   }
   if (ok)
      printf("   Command successful.\n");
   else
   {
      fprintf(stderr, "   Command NOT succesful!\n\n");
      close(sg_fd);
      exit(1);
   }

   /* Close device file */
   printf("Close device file ...\n");
   close(sg_fd);
   printf("   Done.\n");

   /* Exit */
   printf("\nExiting ...\n\n");
   exit(0);
}

/* EOF */
