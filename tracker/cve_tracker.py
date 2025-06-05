import json
import os
import smtplib
import ssl
import zipfile
from datetime import datetime
from email.mime.text import MIMEText
from getpass import getpass
from time import strftime, strptime
from urllib import request

import demisto_client
from demisto_client.demisto_api.rest import ApiException

# read config file
with open('tracker_config.json', 'r') as config_file:
    CONFIG = json.load(config_file)

# set frequently used config variables
provider = CONFIG['source']['provider']
source_folder = CONFIG['source']['sourceFolder']
cve_years = CONFIG['source']['cveYears']
products = CONFIG['source']['products']
dest_folder = CONFIG['resultfile']['destinationFolder']

# check if any existing result CSV files are there
past_tracked = ""
if os.path.exists(dest_folder):
    for file in os.listdir(dest_folder):
        # read each existing file
        with open(dest_folder + '/' + file, 'r') as past_file:
            past_tracked += past_file.read()
# convert records from previous runs to a list of CVEs
past_tracked = past_tracked.split("\n")


def get_cves():
    # check if source folder for the CVE files exist and create it if it doesn't
    if not os.path.exists(source_folder):
        os.makedirs(source_folder)
    # download the CVE files as a zipped folder
    try:
        ssl._create_default_https_context = ssl._create_unverified_context
        request.urlretrieve(provider, source_folder + "/cve_list.zip")
    except Exception as e:
        print(e)
        print("Could not download the requested source json. Cancelling execution...")
        exit()
    # extract the downloaded zip
    with zipfile.ZipFile(source_folder + "/cve_list.zip", 'r') as zip_ref:
        zip_ref.extractall(source_folder + "/cve_list_extracted")


def collect_cves(directory_name):
    cve_files = []
    tracked_cves = []
    # collect files for the years specified in the config file
    for year in cve_years:
        for subfolder in os.listdir(directory_name + year + '/'):
            for cve_f in os.listdir(directory_name + year + '/' + subfolder + '/'):
                cve_files.append(os.path.join(directory_name + year + '/' + subfolder + '/', cve_f))

    for cve_f in cve_files:
        with open(cve_f, 'r') as cve_file:
            file_content = json.load(cve_file)
            # check if the vendor and product match any of the vendor-product combinations specified in the config
            # use CNA container to do so
            for prod in products:
                for key, value in prod.items():
                    i = 0
                    try:
                        while i < len(file_content['containers']['cna']['affected']):
                            # check if vendor matches
                            try:
                                if file_content['containers']['cna']['affected'][i]['vendor'] == key:
                                    # check if the CVE is new or has been updated
                                    consider = False
                                    if not file_content['cveMetadata']['cveId'] in str(past_tracked):
                                        # CVE does not appear in the past files
                                        consider = True
                                    else:
                                        # CVE appears in the past files and might need to be updated
                                        for row in past_tracked:
                                            curr_cve_update = strptime(str(file_content['cveMetadata']['dateUpdated']).split(".")[0].replace("T", " "), "%Y-%m-%d %H:%M:%S")
                                            curr_row_update = strptime(str(row.split(";")[3]), "%Y-%m-%d %H:%M:%S")
                                            if curr_cve_update > curr_row_update:
                                                consider = True
                                                break
                                    # if it was updated or is new
                                    if consider:
                                        for prd in value:
                                            # check if any of the products matches
                                            if prd in file_content['containers']['cna']['affected'][i]['product']:
                                                # avoid duplicates
                                                for tracked in tracked_cves:
                                                    if file_content['cveMetadata']['cveId'] == tracked['cveMetadata']['cveId']:
                                                        break
                                                else:
                                                    tracked_cves.append(file_content)
                                                break
                            except:
                                'continue'
                            i += 1
                    except:
                        continue

    # return the content of the files
    return tracked_cves


def built_result_records(cves):
    # variable with headings of the CSV result file
    cve_entries = "ID;DateReserved;DatePublished;LastUpdated;Title;Description;Vendor-Product-Combination;Metrics;ReferenceURLs\n"
    # format the CVEs
    for cve in cves:
        i = 0
        # get vendor-product combinations
        affected = ""
        while i < len(cve['containers']['cna']['affected']):
            affected += cve['containers']['cna']['affected'][i]['vendor'] + " - " + cve['containers']['cna']['affected'][i]['product'] + "|"
            i += 1

        # get metrics
        def get_metrics(metr, m):
            i= 0
            while i < len(metr):
                # try the assignment as values might not be available for all fields
                try:
                    availability = metr[i]['cvssV3_1']['availabilityImpact'] + "|"
                except:
                    availability =  "n/a|"

                try:
                    integrity = metr[i]['cvssV3_1']['integrityImpact'] + "|"
                except:
                    integrity =  "n/a|"

                try:
                    confi = metr[i]['cvssV3_1']['confidentialityImpact'] + "|"
                except:
                    confi =  "n/a|"

                try:
                    attackComplexity = metr[i]['cvssV3_1']['attackComplexity'] + "|"
                except:
                    attackComplexity =  "n/a|"

                try:
                    vector = metr[i]['cvssV3_1']['attackVector']
                except:
                    vector = "n/a"

                m += str(metr[i]['cvssV3_1']['version']) + "|" + str(metr[i]['cvssV3_1']['baseScore']) + "|" + metr[i]['cvssV3_1']['baseSeverity'] + "|" + metr[i]['cvssV3_1']['vectorString'] + "|" + availability + integrity + confi + attackComplexity + vector + "||"
                break
            return m

        metrics = ""
        j = 0
        try:
            container = cve['containers']['cna']['metrics']
            metrics = get_metrics(container, metrics)
        except:
            while j < len(cve['containers']['adp']):
                try:
                    container = cve['containers']['adp'][j]['metrics']
                    metrics = get_metrics(container, metrics)
                    break
                except:
                    j += 1
                    continue

        # get references
        i= 0
        refs = ""
        try:
            while i < len(cve['containers']['cna']['references']):
                refs += cve['containers']['cna']['references'][i]['url'] + "|"
                i += 1
        except:
            'continue'

        # get title from CNA or ADP container
        try:
            title = cve['containers']['cna']['title'].replace("\n", "")
        except:
            title = cve['containers']['adp'][0]['title'].replace("\n", "")

        # build cve record and add it to the list
        cve_record = cve['cveMetadata']['cveId'] + ";" + str(cve['cveMetadata']['dateReserved']).split(".")[0].replace("T", " ") +  ";" + str(cve['cveMetadata']['datePublished']).split(".")[0].replace("T", " ") + ";" + str(cve['cveMetadata']['dateUpdated']).split(".")[0].replace("T", " ") + ";" + title + ";" + cve['containers']['cna']['descriptions'][0]['value'].replace("\n", "") + ";" + affected + ";" + metrics + ";" + refs + "\n"
        cve_entries += cve_record
    return cve_entries


def write_file(file_content):
    # check if destination folder exists and create it if it doesn't
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    # write result file in the destination folder containing the date and time of creation
    now = strftime("%Y-%m-%d_%H%M%S", datetime.now().timetuple())
    with open(dest_folder + '/' + str(now) + '_CVE-extract.csv', 'w', encoding="utf-8") as result_file:
        result_file.write(file_content)


def send_to_cortex(data):
    # specify instance
    base = CONFIG['CortexXSOARAPIConfig']['host']
    api_instance = demisto_client.configure(base_url=base, debug=False, verify_ssl=ssl.CERT_NONE, api_key=CONFIG['CortexXSOARAPIConfig']['apiKey'])
    # split CVEs and remove header line and last empty line
    single_cves = data.split("\n")
    single_cves = single_cves[1:-1]

    for cve in single_cves:
        # create values to be integrated
        cve = cve.split(";")
        cve_id = cve[0]
        title = cve[4]
        description = cve[5]
        try:
            references = cve[8]
        except:
            references = "n/a"

        # search current cve by ID
        indicator_filter = demisto_client.demisto_api.IndicatorFilter()
        indicator_filter.query = CONFIG['CortexXSOARAPIConfig']['searchField'] + ':"' + cve_id + '"'
        found_indicator = api_instance.indicators_search(indicator_filter=indicator_filter)

        if found_indicator.total == 1:
            # update existing record
            print("Updating CVE " + cve_id)
            update_record(cve, api_instance)
        elif found_indicator.total == 0:
            # create new basic cve indicator object
            ioc_object = {
                "indicator": {
                    "CustomFields": {
                        'title': title,
                        'description': description,
                        'referenceurls': references.replace("|", "\n"),
                        'metrics': [],
                        'vulnerableproducts': []
                    },
                    "indicator_type": "CVE",
                    "last_seen": datetime.now(),
                    'first_seen': datetime.now(),
                    'score': 3,
                    "value": cve_id
                }
            }
            # API integration
            try:
                api_instance.indicators_create(ioc_object=ioc_object)
                print("Created CVE " + cve_id)
                # update the newly created indicator object with the details
                update_record(cve, api_instance)
            except ApiException as e:
                print(e)
                print("Error while writing " + cve_id + " to Cortex XSOAR")


def update_record(cve, api_instance):
    # create values to be updated
    cve_id = cve[0]
    date_reserved = cve[1]
    date_published = cve[2]
    last_updated = cve[3]
    title = cve[4]
    description = cve[5]
    vendor_product = cve[6]
    metrics = cve[7]
    try:
        references = cve[8]
    except:
        references = "n/a"

    # search current cve by ID
    indicator_filter = demisto_client.demisto_api.IndicatorFilter()
    indicator_filter.query = CONFIG['CortexXSOARAPIConfig']['searchField'] + ':"' + cve_id + '"'
    found_indicator = api_instance.indicators_search(indicator_filter=indicator_filter)

    # update cve indicator entry
    ioc_object = demisto_client.demisto_api.IocObject(found_indicator.ioc_objects[0])
    # Mapping of existing standard fields
    ioc_object.custom_fields = found_indicator.ioc_objects[0]['CustomFields']
    ioc_object.calculated_time = found_indicator.ioc_objects[0]['calculatedTime']
    ioc_object.first_seen = found_indicator.ioc_objects[0]['timestamp']
    ioc_object.first_seen_entry_id = found_indicator.ioc_objects[0]['firstSeenEntryID']
    ioc_object.id = found_indicator.ioc_objects[0]['id']
    ioc_object.indicator_type = found_indicator.ioc_objects[0]['indicator_type']
    ioc_object.last_seen = datetime.now()
    ioc_object.last_seen_entry_id = found_indicator.ioc_objects[0]['lastSeenEntryID']
    ioc_object.modified = found_indicator.ioc_objects[0]['modified']
    ioc_object.score = found_indicator.ioc_objects[0]['score']
    ioc_object.sort_values = found_indicator.ioc_objects[0]['sortValues']
    ioc_object.timestamp = found_indicator.ioc_objects[0]['timestamp']
    ioc_object.value = found_indicator.ioc_objects[0]['value']
    ioc_object.version = found_indicator.ioc_objects[0]['version']
    # values from the current CVE
    ioc_object.custom_fields['datereserved'] = date_reserved,
    ioc_object.custom_fields['publishdate'] = date_published,
    ioc_object.custom_fields['updateddate'] = last_updated,
    ioc_object.custom_fields['title'] = title
    ioc_object.custom_fields['description'] = description
    ioc_object.custom_fields['referenceurls'] = references.replace("|", "\n")
    for cpe in vendor_product.split("|")[0:-1]:
        ioc_object.custom_fields['vulnerableproducts'].append({'CPE': cpe})
    for val in metrics.split("||")[0:-1]:
        ioc_object.custom_fields['metrics'].append({'version': val.split("|")[0], 'score': val.split("|")[1], 'severity': val.split("|")[2], 'vector': val.split("|")[3], 'confidentialityimpact': val.split("|")[4], 'integrityimpact': val.split("|")[5], 'availabilityimpact': val.split("|")[6], 'attackcomplexity': val.split("|")[7], 'attackvector': val.split("|")[8]})
    # API integration
    try:
        api_instance.indicators_edit(ioc_object=ioc_object)
    except ApiException as e:
        print(e)
        print("Error while writing " + cve_id + " to Cortex XSOAR")


def send_mail_alert(mailtext):
    # use encrypted connection to the mailserver
    port = 465
    # prompt for mail account password
    sender_mail = str(CONFIG['mailconfig']['senderMailAddress'])
    password = getpass("Enter password for sending mail account: ")
    # get destination mail address and subject from config file
    receiver = str(CONFIG['mailconfig']['destinationMailAddress'])
    subject = str(CONFIG['mailconfig']['mailSubject'])
    # Create SSL context
    context = ssl.create_default_context()
    # define whether CVEs have been updated or the placeholder text should be sent
    if not str(mailtext) == '':
        # create mail message
        single_cves = mailtext.split("\n")
        single_cves = single_cves[1:-1]
        message_text = "Following CVEs have been updated or were newly created:\n\n"
        for cve in single_cves:
            message_text += " - " + cve.split(";")[0] + ": " + cve.split(";")[4] + ", Affected Products: " + cve.split(";")[6].replace("|", ";") + "\n"
        message = MIMEText(message_text)
    else:
        message = MIMEText(str(CONFIG['mailconfig']['placeholderText']))

    try:
        # connect to the mailserver and send mail
        with smtplib.SMTP_SSL(CONFIG['mailconfig']['mailServer'], port, context=context) as server:
            server.login(sender_mail, password)
            message["Subject"] = subject
            message["From"] = sender_mail
            message["To"] = receiver
            server.sendmail(sender_mail, receiver, str(message))
            server.quit()
    except Exception as e:
        # try disconnect
        try:
            server.quit()
        except:
            'disconnected'
        print('Error sending mail. Error message: ' + str(e))
        retry = input('Retry connection and sending mail [y/n]? ')
        # try again or skip
        if retry.upper() == "Y":
            send_mail_alert(result)
        else:
            print("Skipping mailing function")


if __name__ == '__main__':
    print('\n')
    print('++++++++++++++++++++++++++++++++++++++++++ CVE TRACKER SCRIPT START ++++++++++++++++++++++++++++++++++++++++++')

    # download and extract current version of CVE list from the repository
    print("Getting current CVE files")
    get_cves()

    # read the CVE files
    print("Extracting CVEs for the products specified in the config file")
    cves = collect_cves(source_folder + '/cve_list_extracted/cvelistV5-main/cves/')

    # build the result records with only those CVEs that are needed
    print("Checking for updates or new CVEs")
    result = built_result_records(cves)

    # write the result file
    if CONFIG['resultfile']['createFile']:
        print("Writing result file with updated and new CVEs")
        write_file(result)

    # write any new and updated CVEs to Cortex
    if CONFIG['createCVEsInCortex']:
        print("Integrating CVEs to Cortex instance")
        send_to_cortex(result)

    # send notification mail
    if CONFIG['mailconfig']['sendMailAlert']:
        print("Sending mail alert")
        send_mail_alert(result)

    print('+++++++++++++++++++++++++++++++++++++++++++++++++ SCRIPT END +++++++++++++++++++++++++++++++++++++++++++++++++')