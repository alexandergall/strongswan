/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "kernel_snabb_ipsec.h"

#include <daemon.h>
#include <collections/hashtable.h>
#include <collections/array.h>

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

/* Default location of Snabb shm directory and file extenstion */
#define SNABB_SHM_DIR "/var/run/snabb/ipsec"
#define SNABB_SHM_SUFFIX ".ipsec_sa"

typedef struct private_kernel_snabb_ipsec_t private_kernel_snabb_ipsec_t;

/**
 * Private data
 */
struct private_kernel_snabb_ipsec_t {

    /**
     * Public interface
     */
    kernel_ipsec_t public;

    /**
     * Rekey listener
     */
    listener_t listener;

    /**
     * Allocated SPI in host byte order
     */
    uint32_t spi;

    /**
     * Installed SAs
     */
    hashtable_t *sas;

    /**
     * Base path for shmem segments
     */
    char *shm_path;

    /**
     * Suffix of shmem files
     */
    char *shm_suffix;
};

/**
 * Global instance
 */
static private_kernel_snabb_ipsec_t *instance;

/**
 * Data about installed IPsec SAs
 */
typedef struct {
    /**
     * SPI of the SA
     */
    uint32_t spi;

    /**
     * Remote address
     */
    host_t *src;

    /**
     * Local address
     */
    host_t *dst;

    /**
     * Hash over the catenation of source and destination traffic
     * selectors
     */
    u_int ts_hash;

    /** * Associated IKE_SA
     */
    ike_sa_t *ike_sa;

    /**
     * Direction
     */
    bool inbound;

    /**
     * TRUE if this was an SPI allocated by get_spi(). This will
     * be checked by add_sa() and toggled to FALSE.
     */
    bool alloc;

} entry_t;

/**
 * Hash an IPsec SA entry
 */
static u_int entry_hash(const void *key)
{
    entry_t *entry = (entry_t*)key;
    return chunk_hash_inc(chunk_from_thing(entry->spi),
                          chunk_hash_inc(chunk_from_thing(entry->src),
                                         chunk_hash_inc(chunk_from_thing(entry->dst),
                                                        chunk_hash(chunk_from_thing(entry->ike_sa)))));
}

/**
 * Compare an IPsec SA entry
 */
static bool entry_equals(const void *key, const void *other_key)
{
    entry_t *a = (entry_t*)key, *b = (entry_t*)other_key;
    return a->spi == b->spi && a->src == b->src && a->dst == b->dst
        && a->ike_sa == b->ike_sa;
}

int open_shm(private_kernel_snabb_ipsec_t *this, u_int hash, bool inbound,
             struct snabb_ipsec_sa **sa)
{
    int fd;
    char path[PATH_MAX];

    if (snprintf(path, sizeof(path), "%s/%08x/%s%s", this->shm_path, hash,
                 inbound ? "in" : "out", this->shm_suffix) >= sizeof(path))
    {
        DBG1(DBG_KNL, "kernel_snabb: truncated path %s", path);
        return -1;
    }

    if ((fd = open(path, O_RDWR)) == -1)
    {
        DBG1(DBG_KNL, "kernel_snabb: can't open %s: %s", path, strerror(errno));
        return -1;
    }

    *sa = (struct snabb_ipsec_sa *)mmap(NULL, sizeof(*sa),
                                        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (sa == MAP_FAILED)
    {
        DBG1(DBG_KNL, "kernel_snabb: mmap of %s failed: %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/**
 * Write the tuple (spi, replay_window, enc_alg, enc_key) to a shared
 * memory segmen to be read by the Snabb pseudo-kernel.
 */
bool write_sa_to_shm(private_kernel_snabb_ipsec_t *this, u_int hash, bool inbound,
                       uint32_t spi, uint16_t enc_alg, uint32_t replay_window, chunk_t enc_key)
{
    int fd;
    struct snabb_ipsec_sa *sa;
    struct timespec tp;

    if ((fd = open_shm(this, hash, inbound, &sa)) == -1)
        return FALSE;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) == -1)
    {
        DBG1(DBG_KNL, "kernel_snabb: clock_gettime failed: %s", strerror(errno));
        return FALSE;
    }

    sa->spi = ntohl(spi);
    sa->tstamp = tp.tv_sec;
    sa->replay_window = replay_window;
    sa->enc_alg = enc_alg;
    memcpy((void *)&sa->enc_key.aes_gcm_icv16, enc_key.ptr, enc_key.len);

    if (munmap((void *)sa, sizeof(*sa)) == -1)
    {
        DBG1(DBG_KNL, "kernel_snabb: munmap failed: %s", strerror(errno));
        close(fd);
        return FALSE;
    }

    close(fd);
    return TRUE;
}

u_int hash_src_dst(chunk_t src, chunk_t dst)
{
    u_char buf[src.len + dst.len];

    return chunk_hash_static(chunk_create_cat(buf, "cc", src, dst));
}

METHOD(kernel_ipsec_t, get_spi, status_t,
       private_kernel_snabb_ipsec_t *this,
       host_t *src, host_t *dst, uint8_t protocol, uint32_t *spi)
{
    entry_t *entry;

    *spi = htonl(this->spi++);
    INIT(entry,
         .spi = *spi,
         .src = src,
         .dst = dst,
         .ike_sa = charon->bus->get_sa(charon->bus),
         .alloc = TRUE,
        );
    entry = this->sas->put(this->sas, entry, entry);
    assert(!entry);
    return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
       private_kernel_snabb_ipsec_t *this, host_t *src, host_t *dst, uint16_t *cpi)
{
    return FAILED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
       private_kernel_snabb_ipsec_t *this, kernel_ipsec_sa_id_t *id,
       kernel_ipsec_add_sa_t *data)
{
    entry_t *entry, *old_entry;
    traffic_selector_t *src_ts, *dst_ts;

    INIT(entry,
         .spi = id->spi,
         .src = id->src,
         .dst = id->dst,
         .ike_sa = charon->bus->get_sa(charon->bus),
         .inbound = data->inbound
        );

    if (data->inbound)
    {
        /* An inbound SA must have been allocated by get_spi().  This
           checks for the existence of the SA and updates the entry
           with the alloc flag cleared.
        */
        old_entry = this->sas->put(this->sas, entry, entry);
        assert(old_entry && old_entry->alloc);
        free(old_entry);
    }
    else
    {
        /* Add an outbound SA and check that it did not already exist. */
        old_entry = this->sas->put(this->sas, entry, entry);
        assert(!old_entry);
    }

    if (data->enc_alg != ENCR_AES_GCM_ICV16)
    {
        DBG1(DBG_KNL, "kernel_snabb: unsupported encryption algorithm: %N",
             encryption_algorithm_names, data->enc_alg);
        return FAILED;
    }

    if (!data->esn) {
        DBG1(DBG_KNL, "kernel_snabb: ESN required");
        return FAILED;
    }

    if (data->src_ts->get_count(data->src_ts) != 1 ||
        data->dst_ts->get_count(data->dst_ts) != 1)
    {
        DBG1(DBG_KNL, "kernel_snabb: expected single traffic selector per direction, got %#R, %#R",
             data->src_ts, data->dst_ts);
        return FAILED;
    }

    if (data->inbound)
    {
        data->src_ts->get_first(data->src_ts, (void *)&src_ts);
        data->dst_ts->get_first(data->dst_ts, (void *)&dst_ts);
    }
    else
    {
        data->src_ts->get_first(data->src_ts, (void *)&dst_ts);
        data->dst_ts->get_first(data->dst_ts, (void *)&src_ts);
    }

    if (src_ts->is_host(src_ts, NULL) &&
        dst_ts->is_host(dst_ts, NULL))
    {
        u_int hash = hash_src_dst(src_ts->get_from_address(src_ts),
                                  dst_ts->get_to_address(dst_ts));

        entry->ts_hash = hash;
        if (!write_sa_to_shm(this, hash, data->inbound, id->spi, data->enc_alg,
                             data->replay_window, data->enc_key))
            return FAILED;
    }
    else
    {
        DBG1(DBG_KNL, "kernel_snabb: non-host traffic selector %R, %R",
             src_ts, dst_ts);
        return FAILED;
    }

    return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
       private_kernel_snabb_ipsec_t *this, kernel_ipsec_sa_id_t *id,
       kernel_ipsec_update_sa_t *data)
{
    /* TODO */
    return SUCCESS;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
       private_kernel_snabb_ipsec_t *this, kernel_ipsec_sa_id_t *id,
       kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
       time_t *time)
{
    /* Could be implemented by letting the Snabb pseudo-kernel supply
     * the data via he shm segment. */
    return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
       private_kernel_snabb_ipsec_t *this, kernel_ipsec_sa_id_t *id,
       kernel_ipsec_del_sa_t *data)
{
    int fd;
    struct snabb_ipsec_sa *sa;

    entry_t *entry, lookup = {
        .spi = id->spi,
        .src = id->src,
        .dst = id->dst,
        .ike_sa = charon->bus->get_sa(charon->bus),
    };

    entry = this->sas->remove(this->sas, &lookup);
    assert(entry);
    if (!entry->alloc && entry->ts_hash != 0 &&
        (fd = open_shm(this, entry->ts_hash, entry->inbound, &sa)) > -1)
    {
        if (sa->spi == ntohl(id->spi))
            sa->spi = 0;
        close(fd);
    }
    free(entry);
    return SUCCESS;
}

METHOD(listener_t, ike_rekey, bool,
       listener_t *listener, ike_sa_t *old, ike_sa_t *new)
{
    enumerator_t *enumerator;
    array_t *sas = NULL;
    entry_t *entry;

    enumerator = instance->sas->create_enumerator(instance->sas);
    while (enumerator->enumerate(enumerator, &entry, NULL))
    {
        if (entry->ike_sa == old)
        {
            instance->sas->remove_at(instance->sas, enumerator);
            array_insert_create(&sas, ARRAY_TAIL, entry);
        }
    }
    enumerator->destroy(enumerator);
    enumerator = array_create_enumerator(sas);
    while (enumerator->enumerate(enumerator, &entry))
    {
        array_remove_at(sas, enumerator);
        entry->ike_sa = new;
        entry = instance->sas->put(instance->sas, entry, entry);
        assert(!entry);
    }
    enumerator->destroy(enumerator);
    array_destroy(sas);
    return TRUE;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
       private_kernel_snabb_ipsec_t *this, kernel_ipsec_policy_id_t *id,
       kernel_ipsec_manage_policy_t *data)
{
    return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
       private_kernel_snabb_ipsec_t *this, kernel_ipsec_policy_id_t *id,
       kernel_ipsec_query_policy_t *data, time_t *use_time)
{
    *use_time = 1;
    return SUCCESS;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
       private_kernel_snabb_ipsec_t *this, kernel_ipsec_policy_id_t *id,
       kernel_ipsec_manage_policy_t *data)
{
    return SUCCESS;
}

METHOD(kernel_ipsec_t, destroy, void,
       private_kernel_snabb_ipsec_t *this)
{
    charon->bus->remove_listener(charon->bus, &this->listener);
    this->sas->destroy(this->sas);
    free(this);
}

/*
 * Described in header
 */
kernel_ipsec_t *kernel_snabb_ipsec_create()
{
    private_kernel_snabb_ipsec_t *this;

    INIT(this,
         .public = {
             .get_spi = _get_spi,
                 .get_cpi = _get_cpi,
                 .add_sa = _add_sa,
                 .update_sa = _update_sa,
                 .query_sa = _query_sa,
                 .del_sa = _del_sa,
                 .flush_sas = (void*)return_failed,
                 .add_policy = _add_policy,
                 .query_policy = _query_policy,
                 .del_policy = _del_policy,
                 .flush_policies = (void*)return_failed,
                 .bypass_socket = (void*)return_true,
                 .enable_udp_decap = (void*)return_true,
                 .destroy = _destroy,
                 },
         .listener = {
             .ike_rekey = _ike_rekey,
                  },
         .spi = 256,
         .sas = hashtable_create(entry_hash, entry_equals, 8),
         .shm_path = lib->settings->get_str(lib->settings,
                                            "%s.plugins.kernel-snabb.shm_path",
                                            SNABB_SHM_DIR, lib->ns),
         .shm_suffix = lib->settings->get_str(lib->settings,
                                              "%s.plugins.kernel-snabb.shm_suffix",
                                              SNABB_SHM_SUFFIX, lib->ns),
        );

    instance = this;

    charon->bus->add_listener(charon->bus, &this->listener);

    return &this->public;
}


CALLBACK(filter_sas, bool,
         void *data, enumerator_t *orig, va_list args)
{
    entry_t *entry;
    ike_sa_t **ike_sa;
    uint32_t *spi;

    VA_ARGS_VGET(args, ike_sa, spi);

    while (orig->enumerate(orig, &entry, NULL))
    {
        if (entry->alloc)
        {
            continue;
        }
        *ike_sa = entry->ike_sa;
        *spi = entry->spi;
        return TRUE;
    }
    return FALSE;
}

/*
 * Described in header
 */
enumerator_t *kernel_snabb_ipsec_create_sa_enumerator()
{
    return enumerator_create_filter(
        instance->sas->create_enumerator(instance->sas),
        filter_sas, NULL, NULL);
}
