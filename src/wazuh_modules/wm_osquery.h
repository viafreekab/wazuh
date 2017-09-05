/*
 * Wazuh Module for OSquery
 * Copyright (C) 2017 Wazuh Inc.
 * September 5, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_OSQUERY
#define WM_OSQUERY

#define WM_OSQUERY_DEF_INTERVAL 3600        // Default cycle interval (1 hour)
#define WM_OSQUERY_LOGTAG ARGV0 ":osquery"  // Tag for log messages

typedef struct wm_osquery {
    wm_osquery_flags flags;
    wm_osquery_query *queries;
    char * config_path;
} wm_osquery;

typedef struct wm_osquery_flags {
    unsigned int enabled:1;
    unsigned int scan_on_start:1;
    unsigned int error:1;
} wm_osquery_flags;

typedef enum wm_osquery_type {
    OS,
    NETWORK,
    PORTS,
    PIDS,
    FILES,
    CUSTOM,
    PACK
} wm_osquery_type;

typedef struct wm_osquery_query {
    wm_osquery_type type;
    int interval;
    char *fields;
    char *query;
    char *description;
    char *path;
    char *name;
    wm_osquery_query next;
} wm_osquery_query;

extern const wm_context WM_OSQUERY_CONTEXT; // Context

// Parse XML configuration
int wm_osquery_read(XML_NODE node, wmodule *module);

#endif
