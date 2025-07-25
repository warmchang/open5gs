/*
 * Copyright (C) 2019-2024 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SMF_NSMF_HANDLER_H
#define SMF_NSMF_HANDLER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

bool smf_nsmf_handle_create_sm_context(
    smf_sess_t *sess, ogs_sbi_stream_t *stream, ogs_sbi_message_t *message);
bool smf_nsmf_handle_update_sm_context(
    smf_sess_t *sess, ogs_sbi_stream_t *stream, ogs_sbi_message_t *message);
bool smf_nsmf_handle_release_sm_context(
    smf_sess_t *sess, ogs_sbi_stream_t *stream, ogs_sbi_message_t *message);

bool smf_nsmf_handle_create_data_in_hsmf(
    smf_sess_t *sess, ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool smf_nsmf_handle_created_data_in_vsmf(
    smf_sess_t *sess, ogs_sbi_message_t *recvmsg);

bool smf_nsmf_handle_update_data_in_hsmf(
    smf_sess_t *sess, ogs_sbi_stream_t *stream, ogs_sbi_message_t *message);
bool smf_nsmf_handle_update_data_in_vsmf(
    smf_sess_t *sess, ogs_sbi_stream_t *stream, ogs_sbi_message_t *message);

bool smf_nsmf_handle_release_data_in_hsmf(
    smf_sess_t *sess, ogs_sbi_stream_t *stream, ogs_sbi_message_t *message);

bool smf_nsmf_callback_handle_sdm_data_change_notify(
    ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);

#ifdef __cplusplus
}
#endif

#endif /* SMF_NSMF_HANDLER_H */
