# CVE Tracker

## Description

This repo contains a script to track the CVEs related to vulnerabilities in the products specified in the config file.
By default, it gets the CVEs from the [official CVEProject Github repo](https://github.com/CVEProject/cvelistV5/).<br/>
The default installation contains ten test files to test the CVE Tracking with a small number of CVEs (five related to Apple and five related to Microsoft).
The behaviour of the script is as follows:<br/>
 1. Download and extract the current CVEs from the CVEProject repo<br/>
 2. Extract the relevant CVEs from the folder and products specified in the config. By default, these are the *Microsoft Windows 10 and 11* and the *Apple iOS and iPadOS* vulnerabilities from the *TEST* folder<br/>
 3. Extract only the relevant information from the CVE records. The information is primarily retrieved from the CNA container, but may be extracted from ADP container if it is not available in the CNA container. The information to be extracted are defined in the code as:<br/>
 - CVE ID
 - Date Reserved
 - Date Published
 - Date Updated
 - Title
 - Description
 - Vendor-Product-Combinations (*containers - cna - affected - vendor/product*)
 - Metrics (*containers - cna - affected - cvssV3_1*: version, baseScore, baseSeverity, vectorString, availabilityImpact, integrityImpact, confidentialityImpact, attackComplexity, attackVector)
 - Reference URLs (if any)
 4. Create CSV file containing the new or updated CVEs. This is done only if the respective setting in the config is set. The files will then be stored in the destination folder configured<br/>
 5. If a Cortex instance is specified and the respective setting is switched on, the CVEs can be integrated as indicators to the respective instance of the PA Cortex XSOAR<br/>
 6. If the setting is switched on in the config, a mail alert with the CVE IDs, the title and the vendor-product-combinations is sent<br/>

This work is licensed under an MIT License.<br/>
© 2025 Sandra Liedtke.

## Configurations

 - `source` `provider`: The source from where the CVE records are downloaded. The CVE files are downloaded as zip folder and extracted by the script. The default setting points to the download link of the [official CVEProject Github repo](https://github.com/CVEProject/cvelistV5/) and should not be changed unless the CVEs can be downloaded from a different source in the same format
 - `source` `sourceFolder`: The folder name where the downloaded and extracted CVE files are stored. The default folder contains a *TEST* subfolder which is not part of the official repo, but was created to test the script with a limited number of CVE records
 - `source` `cveYears`: The Years which will be considered. Only the CVE files of the respective subfolders will be handled. The default value is *TEST* and should be changed to at least the current year once the script is used in production
 - `source` `products`: A list of Vendor-Product-Combinations that will be tracked. The Vendor is used as key, must be unique and must match the vendor given in the related CVEs. If the CVE record contains any of the products of the respective vendor, the vulnerability is tracked. As per the default configuration, all CVEs are tracked if the vendor is *Microsoft* and any of the products is either *Windows 10* or *Windows 11* or if the vendor is *Apple* and any of the products is either *iOS* or *IPadOS*
 - `resultfile` `createFile`: Defines if a CSV file containing all considered CVEs should be created. This is switched on by default.
 - `resultfile` `destinationFolder`: Defines the folder name of the subdirectory where the CSV files will be stored. If the folder does not exist in the directory of the script, the script will create it
 - `mailconfig` `sendMailAlert`: Defines whether a mail summary should be sent. By default this setting is switched off. When enabled, a mail server, sending mail account and destination mail address must be given
 - `mailconfig` `mailServer`: The mail server of the sending mail account
 - `mailconfig` `senderMailAddress`: The mail address of the sending mail account. The password will be requested as input on the terminal and should not be stored as clear text in the config file or in the code
 - `mailconfig` `destinationMailAddress`: The receiving mail address. This can also be the same as the sending mail address
 - `mailconfig` `mailSubject`: The subject of the mail to be sent
 - `mailconfig` `placeholderText`: A Placeholder that will be sent as mail body if no CVEs related to the specified products are updated or created new
 - `createCVEsInCortex`: Defines whether the CVE records should be integrated to a Cortex XSOAR instance. The setting is disabled per default. When enabled, the CVE indicator type of the Cortex instance specified must be able to handle the values as displayed in the result file
 - `CortexXSOARAPIConfig` `host`: The host url of the Cortex instance to which the records should be integrated
 - `CortexXSOARAPIConfig` `apiKey`: The API key used to authenticate
 - `CortexXSOARAPIConfig` `searchField`: The search field, by which the indicators can be identified. By default this will be the *value' field of the records as it contains the CVE ID

## System Requirements

 - Python 3.10 or higher
 - The following libraries are needed:
     - json
     - os
     - smtplib
     - ssl
     - zipfile
     - datetime
     - email
     - getpass
     - time
     - urllib
 - A text editor, Libre Calc or Excel to open the generated CSV files
 - If the mail alert functionality is used, a sending mail account is needed
 - If the Cortex Integration is used, an instance of the Palo Alto Cortex XSOAR should be available and API Integration must be enabled
