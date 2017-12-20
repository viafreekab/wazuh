#!/usr/bin/env python
################################################################################
# Wazuh wrapper for Vuls
# Wazuh Inc.
# Dec 19, 2017
################################################################################


from datetime import datetime
from socket import socket, AF_UNIX, SOCK_DGRAM
from subprocess import call
import json
import sys
import getopt

enable_debug = 0

def help():
    print('wazuh-vuls \n' \
    '           [--mincvss 5]*           Minimum score to report.\n' \
    '           [--updatenvd]*           Update NVD database.\n' \
    '           [--nvd-year]                    Year from which the CVE database will be downloaded'
    '           [--updaterh]*          Update Redhat OVAL database.\n' \
    '           [--updateub]          Update Ubuntu OVAL database.\n' \
    '           [--updatedeb]          Update Debian OVAL database.\n' \
    '           [--updateorac]          Update Oracle OVAL database.\n' \
    '           [--autoupdate]          Oval database auto-update.\n' \
    '           [--os-version]  OS version for downloading the OVAL database'
    '           [--onlyupdate]           Only update databases.\n' \
    '           [--source <nvd|redhat>]* CVE database preferred. The default will be the one that takes the highest CVSS.\n' \
    '           [--antiquity-limit 30]*  Warn if vulnerability update date is less than X days.\n' \
    '           [--disable-package-info]*        Disable packages info.\n' \
    '           [--debug]*               Debug mode.\n')

def extract_CVEinfo(cve, type):
    if type == 'nvd':
        source = 'National Vulnerability Database'
    elif type == 'redhat':
        source = 'RedHat OVAL'
    link = cve['CveContents'][type]['SourceLink']
    last_modified = cve['CveContents'][type]['LastModified']
    #summary = cve['CveContents'][type]['Summary']
    return source, link, last_modified

def extract_CVEscore(cve, type):
    cvss2 = cve['CveContents'][type]['Cvss2Score']
    cvss3 = cve['CveContents'][type]['Cvss3Score']
    score = cvss2 if cvss2 > cvss3 else cvss3
    return score

def has_vector(cve, type):
    return type in cve['CveContents']

def change_vector(type):
    return 'nvd' if type == 'redhat' else 'redhat'

def send_msg(wazuh_queue, header, msg):
    msg['integration'] = 'vuls'
    debug(json.dumps(msg, indent=4))
    msg = '{0}{1}'.format(header, json.dumps(msg))
    s = socket(AF_UNIX, SOCK_DGRAM)
    s.connect(wazuh_queue)
    s.send(msg.encode())
    s.close()

def debug(msg):
    if enable_debug:
        print(msg)

def update_oval(OS, version, fetcher, vuls_log, vuls_path):
    if not version:
        print('Error: To update the OVAL database, the OS version must be attached with --os-version. You can do it automatically with --autoupdate.')
        sys.exit(1)
    debug('Updating {0} {1} OVAL database...'.format(OS, version))
    call([fetcher, 'fetch-{0}'.format(OS), '-dbpath={0}/oval.sqlite3'.format(vuls_path), '-log-dir={0}'.format(vuls_log), version])


def main(argv):

    # Wazuh installation path
    wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
    # Vuls installation path
    vuls_path = '{0}/wodles/vuls'.format(wazuh_path)
    # Wazuh queue
    wazuh_queue = '{0}/queue/ossec/queue'.format(wazuh_path)
    # Path to VULS logs
    vuls_log = '{0}/logs/vuls/'.format(wazuh_path)
    # Path to VULS binary
    vuls_bin = '{0}/go/bin/vuls'.format(vuls_path)
    # Path to CVE fetcher
    cve_db_fetcher = '{0}/go/bin/go-cve-dictionary'.format(vuls_path)
    # Path to OVAL fetcher
    oval_db_fetcher = '{0}/go/bin/goval-dictionary'.format(vuls_path)
    # Path to VULS config
    vuls_config = '{0}/config.toml'.format(vuls_path)
    # Path to CVE database
    cve_db = '{0}/cve.sqlite3'.format(vuls_path)
    # Path to OVAL database
    oval_db = '{0}/oval.sqlite3'.format(vuls_path)
    # Minimum CVSS for reporting
    cvss_min = 0
    # CVSS source
    cvss_source=''
    # Message header
    header = '1:Wazuh-VULS:'
    # Notify message header
    notify_header = '9:Wazuh-VULS:'
    # Show packages info
    package_info = 1
    # Minimum antiquity
    antiquity_limit = 0
    # Update databases
    nvd_year = 2002
    update_nvd = 0
    update_rh = 0
    update_ub = 0
    update_deb = 0
    update_orac = 0
    autoupdate = 0
    update_os_version = ''
    only_update = 0

    try:
        opts, args = getopt.getopt(argv,'h',["mincvss=","updatenvd", "nvd-year=", "updaterh", "updateub", "updatedeb", "updateorac", "autoupdate", "os-version=", "disable-package-info", "antiquity-limit=", "debug", "source=", "onlyupdate"])
    except getopt.GetoptError:
        help()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '--updatenvd':
            update_nvd = 1
        elif opt == '--nvd-year':
            nvd_year = int(arg)
        elif opt == '--updaterh':
            update_rh = 1
        elif opt == '--updateub':
            update_ub = 1
        elif opt == '--updatedeb':
            update_deb = 1
        elif opt == '--updateorac':
            update_orac = 1
        elif opt == '--autoupdate':
            autoupdate = 1
        elif opt == '--onlyupdate':
            only_update = 1
        elif opt == '--os-version':
            update_os_version = arg
        elif opt == '--disable-package-info':
            package_info = 0
        elif opt == '--antiquity-limit':
            antiquity_limit = int(arg)
        elif opt == '--mincvss':
            cvss_min = float(arg)
        elif opt == '--source':
            if arg == 'nvd' or arg == 'redhat':
                cvss_source = arg
            else:
                help()
                sys.exit()
        elif opt == '--debug':
            global enable_debug
            enable_debug = 1
        elif opt == '-h':
            help()
            sys.exit()
        else:
            print('Error: Invalid parameter')
            help()
            sys.exit(1)

    msg = {}
    msg['event'] = 'Starting vulnerability scan.'
    send_msg(wazuh_queue, notify_header, msg)

    call([vuls_bin, 'scan', '-results-dir={0}'.format(vuls_log), '-config={0}'.format(vuls_config), '-log-dir={0}'.format(vuls_log)])

    # Extracts the log header
    data = json.load(open('{0}/current/localhost.json'.format(vuls_log)))

    date = data['ScannedAt'].split('.')[0].replace('T', ' ')
    os_family = data['Family']
    os_release = data['Release']
    kernel = data['RunningKernel']['Release']

    if update_nvd:
        debug('Updating NVD database...')
        for i in range(nvd_year, (int(str(datetime.now()).split('-')[0]) + 1)):
            call([cve_db_fetcher, 'fetchnvd', '-dbpath={0}/cve.sqlite3'.format(vuls_path), '-log-dir={0}'.format(vuls_log), '-years', str(i)])

    if update_rh:
        debug('Updating Redhat OVAL database...')
        update_oval('redhat', update_os_version, oval_db_fetcher, vuls_log, vuls_path) #5 6 7
    elif update_ub:
        debug('Updating Ubuntu OVAL database...')
        update_oval('ubuntu', update_os_version, oval_db_fetcher, vuls_log, vuls_path) #12 14 16
    elif update_deb:
        debug('Updating Debian OVAL database...')
        update_oval('debian', update_os_version, oval_db_fetcher, vuls_log, vuls_path) #7 8 9 10
    elif update_orac:
        debug('Updating Oracle OVAL database...')
        update_oval('oracle', update_os_version, oval_db_fetcher, vuls_log, vuls_path) #5 6 7

    if only_update:
        sys.exit()

    call([vuls_bin, 'report', '-format-json', '-ignore-unscored-cves', '-results-dir={0}'.format(vuls_log), '-cvedb-path={0}'.format(cve_db), '-ovaldb-path={0}'.format(oval_db), '-config={0}'.format(vuls_config), '-log-dir={0}'.format(vuls_log)])

    # Send scanned CVEs
    for c, cve in data['ScannedCves'].iteritems():
        if cvss_source:
            source = cvss_source if has_vector(cve, cvss_source) else change_vector(cvss_source)
            score = extract_CVEscore(cve, source)
            source, link, last_modified = extract_CVEinfo(cve, source)
        else:
            # Higher
            nvd_score = extract_CVEscore(cve, 'nvd') if has_vector(cve, 'nvd') else -1
            rh_score = extract_CVEscore(cve, 'redhat') if has_vector(cve, 'redhat') else -1

            if nvd_score > rh_score:
                score = nvd_score
                source, link, last_modified = extract_CVEinfo(cve, 'nvd')
            else:
                score = rh_score
                source, link, last_modified = extract_CVEinfo(cve, 'redhat')

        if score < cvss_min:
            debug('\n{0} has a score lower than {1}. Skipping.'.format(cve['CveID'], cvss_min))
            continue

        msg = {}
        msg['ScanDate'] = date
        msg['OSversion'] = '{0} {1}'.format(os_family, os_version)
        msg['KernelVersion'] = kernel
        msg['ScannedCVE'] = cve['CveID']
        msg['Assurance'] = '{0}%'.format(cve['Confidence']['Score'])
        msg['DetectionMethod'] = cve['Confidence']['DetectionMethod']
        msg['Score'] = score
        msg['Source'] = source
        msg['Link'] = link
        msg['LastModified'] = last_modified.split('.')[0].replace('T', ' ').replace('Z', '')
        msg['AffectedPackages'] = ''

        debug(msg['ScannedCVE'])
        diff = (datetime.now() - datetime.strptime(msg['LastModified'], '%Y-%m-%d %H:%M:%S')).days
        if diff < antiquity_limit:
            msg = {}
            msg['event'] = '{0} has a update date lower than {1} days.'.format(cve['CveID'], antiquity_limit)
            send_msg(wazuh_queue, header, msg)
            debug(msg['event'])

        if package_info:
            msg['AffectedPackagesInfo'] = {}
        # Look for affected packages
        for p in cve['AffectedPackages']:
            name = p['Name']
            package = data['Packages'][name]
            if package_info:
                msg['AffectedPackagesInfo'][name] = {}
                msg['AffectedPackagesInfo'][name]['Version'] = package['Version']
                msg['AffectedPackagesInfo'][name]['Release'] = package ['Release']
                msg['AffectedPackagesInfo'][name]['NewVersion'] = package ['NewVersion']
                msg['AffectedPackagesInfo'][name]['NewRelease'] = package ['NewRelease']
                msg['AffectedPackagesInfo'][name]['Arch'] = package ['Arch']
                msg['AffectedPackagesInfo'][name]['Repository'] = package ['Repository']
                msg['AffectedPackagesInfo'][name]['Fixable'] = 'Yes' if p['NotFixedYet'] == False else 'No'
            msg['AffectedPackages'] = '{0}{1} ({2}), '.format(msg['AffectedPackages'], name,  'Fixable' if p['NotFixedYet'] == False else 'Not fixable')

        msg['AffectedPackages'] = msg['AffectedPackages'][0:-2]

        send_msg(wazuh_queue, header, msg)

    msg = {}
    msg['event'] = 'Ending vulnerability scan.'
    send_msg(wazuh_queue, notify_header, msg)

if __name__ == "__main__":
   main(sys.argv[1:])
