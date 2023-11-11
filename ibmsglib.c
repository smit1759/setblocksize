#ifndef ibmsglib_h
#include "ibmsglib.h"
#endif

/*
 * Scatter/gather list buffers are checked against the value returned
 * by queue_dma_alignment(), which defaults to 511 in Linux 2.6,
 * for alignment if a SG_IO ioctl request is sent through a /dev/sdX device.
 */
#define IPR_S_G_BUFF_ALIGNMENT 512
#define IPR_MAX_XFER 0x8000

const int cdb_size[] = {6, 10, 10, 0, 16, 12, 16, 16};
/**
 * _sg_ioctl -
 * @fd: 		file descriptor
 * @cdb:        	cdb
 * @data:		data pointer
 * @xfer_len            transfer length
 * @data_direction      transfer to dev or from dev
 * @sense_data          sense data pointer
 * @timeout_in_sec      timeout value
 * @retries             number of retries
 *
 * Returns:
 *   0 if success / non-zero on failure
 **/
static int _sg_ioctl(int fd, u8 cdb[IPR_CCB_CDB_LEN],
                     void *data, u32 xfer_len, u32 data_direction,
                     struct sense_data_t *sense_data,
                     u32 timeout_in_sec, int retries)
{
    int rc = 0;
    sg_io_hdr_t io_hdr_t;
    sg_iovec_t *iovec = NULL;
    int iovec_count = 0;
    int i;
    int buff_len, segment_size;
    void *dxferp;
    u8 *buf;
    struct sense_data_t sd;
    struct df_sense_data_t *dfsdp = NULL;

    /* check if scatter gather should be used */
    if (xfer_len > IPR_MAX_XFER)
    {
        iovec_count = (xfer_len / IPR_MAX_XFER) + 1;
        iovec = malloc(iovec_count * sizeof(sg_iovec_t));

        buff_len = xfer_len;
        segment_size = IPR_MAX_XFER;

        for (i = 0; (i < iovec_count) && (buff_len != 0); i++)
        {
            posix_memalign(&(iovec[i].iov_base), IPR_S_G_BUFF_ALIGNMENT, segment_size);
            if (data_direction == SG_DXFER_TO_DEV)
                memcpy(iovec[i].iov_base, data + (IPR_MAX_XFER * i), segment_size);
            iovec[i].iov_len = segment_size;

            buff_len -= segment_size;
            if (buff_len < segment_size)
                segment_size = buff_len;
        }

        iovec_count = i;
        dxferp = (void *)iovec;
    }
    else
    {
        iovec_count = 0;
        dxferp = data;
    }

    for (i = 0; i < (retries + 1); i++)
    {
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
         * In the same u8, the 4th bit of fixed format corresponds
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
        for (i = 0, buf = (u8 *)data; i < iovec_count; i++)
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
                     sense_data, timeout_in_sec, 1);
};

/**
 * ipr_mode_select - issue a mode select command
 * @dev:		ipr dev struct
 * @buff:	        data buffer
 * @length:		length of buffer
 *
 * Returns:
 *   0 if success / non-zero on failure
 **/
int ipr_mode_select(int fd, void *buff, int length)
{
    u8 cdb[IPR_CCB_CDB_LEN];
    struct sense_data_t sense_data;
    int rc;
    if (fd <= 1)
    {
        syslog(LOG_ERR, "Could not open\n");
        return errno;
    }

    memset(cdb, 0, IPR_CCB_CDB_LEN);

    cdb[0] = MODE_SELECT;
    cdb[1] = 0x10; /* PF = 1, SP = 0 */
    cdb[4] = length;

    rc = sg_ioctl(fd, cdb, buff,
                  length, SG_DXFER_TO_DEV,
                  &sense_data, IPR_INTERNAL_TIMEOUT);

    if (rc != 0)
    {
        printf("error issuing MODE SELECT");
    }
    close(fd);
    return rc;
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
    // char *name = dev->gen_name;
    if (fd <= 1)
    {
        syslog(LOG_ERR, "Could not open (format unit)\n");
    }

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
        printf("failed format unit rc");

    close(fd);

    return rc;
}