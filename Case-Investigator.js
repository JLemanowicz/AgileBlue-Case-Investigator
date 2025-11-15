// ==UserScript==
// @name         AgileBlue Case Investigator
// @namespace    http://tampermonkey.net/
// @version      0.15
// @description  Adds "Investigate in Elastic", "Escalate", and "Close as Benign" buttons for supported alerts, with automated narrative handling, email sending, status updates, and IPinfo integration. Includes case assignment button to assign cases to the user, with resolution buttons shown only when assigned. Hides resolution buttons when case is closed.
// @author       Jacob Lemanowicz, Grok
// @match        https://portal.agileblue.com/apps/case/*
// @grant        GM_addStyle
// @grant        GM_xmlhttpRequest
// @connect      ipinfo.io
// @run-at       document-idle
// ==/UserScript==

(function () {
    'use strict';

    // Log script initialization
    console.log('AgileBlue Case Investigator script started at', new Date().toISOString());

    // Define CSS styles for buttons
    GM_addStyle(`
        .investigateElasticButton {
            padding: 5px 10px;
            background-color: #011627;
            border: 1px solid #19AFD2;
            color: #19AFD2;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1.4rem;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            margin-left: 15px;
            vertical-align: middle;
        }
        .investigateElasticButton:hover {
            background-color: #022c43;
            color: #19AFD2;
        }
        .resolutionButton, #assignCaseButton {
            position: fixed;
            z-index: 1000;
            padding: 7.5px 15px;
            background-color: #011627;
            border: 1px solid #19AFD2;
            color: #19AFD2;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1.6rem;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .resolutionButton:hover, #assignCaseButton:hover {
            background-color: #022c43;
            color: #19AFD2;
        }
        #assignCaseButton {
            bottom: 20px;
            right: 20px;
        }
        #escalateButton {
            bottom: 60px;
            right: 20px;
        }
        #closeBenignButton {
            bottom: 20px;
            right: 20px;
        }
        .resolutionButton.hidden, #assignCaseButton.hidden {
            display: none;
        }
        .resolutionButton svg, #assignCaseButton svg {
            width: 16px;
            height: 16px;
            fill: #19AFD2;
        }
    `);

    // IPinfo API token
    const IPINFO_TOKEN = 'ce0a8bab925670';

    // Function to query IPinfo for IP details
    function queryIPInfo(ipAddress) {
        return new Promise((resolve) => {
            console.log(`Querying IPinfo for IP: ${ipAddress}`);
            GM_xmlhttpRequest({
                method: 'GET',
                url: `https://ipinfo.io/${encodeURIComponent(ipAddress)}/json?token=${IPINFO_TOKEN}`,
                headers: {
                    'Accept': 'application/json',
                },
                onload: (response) => {
                    try {
                        const data = JSON.parse(response.responseText);
                        console.log('Full IPinfo response:', data);
                        if (data.city && data.region && data.country) {
                            console.log('IPinfo parsed:', {
                                location: `${data.city}, ${data.region}, ${data.country}`,
                                isp: data.org || 'Unknown'
                            });
                            resolve({
                                location: `${data.city}, ${data.region}, ${data.country}`,
                                isp: data.org || 'Unknown',
                            });
                        } else {
                            console.error('Invalid response structure:', data);
                            resolve({ location: 'Unknown', isp: 'Unknown' });
                        }
                    } catch (error) {
                        console.error('Error parsing IPinfo response:', error);
                        resolve({ location: 'Unknown', isp: 'Unknown' });
                    }
                },
                onerror: (error) => {
                    console.error('IPinfo API request failed:', error);
                    resolve({ location: 'Unknown', isp: 'Unknown' });
                },
            });
        });
    }

    // Define supported alert rules
    const rules = [
        {
            name: 'Cisco Meraki - Unusually Low Log Count',
            elasticLink:
                "https://siem.agileblue.com/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-7d%2Fd,to:now))&_a=(columns:!(event.action,event.ingested),dataSource:(dataViewId:'18e3ccea-a179-47a6-b8b4-d1845f9706a1',type:dataView),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:client_id,negate:!f,params:(query:<id>),type:phrase),query:(match_phrase:(client_id:<id>))),('$state':(store:appState),meta:(alias:!n,disabled:!f,field:event.module,index:'18e3ccea-a179-47a6-b8b4-d1845f9706a1',key:event.module,negate:!f,params:(query:cisco_meraki),type:phrase),query:(match_phrase:(event.module:cisco_meraki)))),hideChart:!f,interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))",
            needsFullLoad: false,
            fields: [
                {
                    placeholder: '<id>',
                    selector: 'input[name="ClientId"]',
                    extractType: 'value',
                },
            ],
            resolutions: {
                escalate: [
                    {
                        client_id: 'default',
                        narrative: 'Escalated to audit cases team',
                        autosave: false,
                        sendEmail: false,
                    },
                ],
                closeBenign: [
                    {
                        client_id: 'default',
                        narrative: 'Closing as false-positive, confirmed that logs are still being ingested in Elastic.\nLast Log Time: \nLast Log Ingested: ',
                        autosave: false,
                        status: 'Closed',
                    },
                ],
            },
        },
        {
            name: 'Office365 - Unusually Low Log Count',
            elasticLink:
                "https://siem.agileblue.com/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-7d%2Fd,to:now))&_a=(columns:!(event.action,event.ingested),dataSource:(dataViewId:'18e3ccea-a179-47a6-b8b4-d1845f9706a1',type:dataView),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:client_id,negate:!f,params:(query:<id>),type:phrase),query:(match_phrase:(client_id:<id>))),('$state':(store:appState),meta:(alias:!n,disabled:!f,field:event.module,index:'18e3ccea-a179-47a6-b8b4-d1845f9706a1',key:event.module,negate:!f,params:(query:o365),type:phrase),query:(match_phrase:(event.module:o365)))),hideChart:!f,interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))",
            needsFullLoad: false,
            fields: [
                {
                    placeholder: '<id>',
                    selector: 'input[name="ClientId"]',
                    extractType: 'value',
                },
            ],
            resolutions: {
                escalate: [
                    {
                        client_id: 'default',
                        narrative: 'Escalated to audit cases team',
                        autosave: false,
                        sendEmail: false,
                    },
                ],
                closeBenign: [
                    {
                        client_id: 'default',
                        narrative: 'Closing as false-positive, confirmed that logs are still being ingested in Elastic.\nLast Log Time: \nLast Log Ingested: ',
                        autosave: false,
                        status: 'Closed',
                    },
                ],
            },
        },
        {
            name: 'GSuite - Unapproved Foreign Country Login',
            elasticLink:
                "https://siem.agileblue.com/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-7d%2Fd,to:now))&_a=(columns:!(event.action,source.ip,source.geo.country_name,source.geo.continent_name,source.as.organization.name,source.geo.region_name),dataSource:(dataViewId:'18e3ccea-a179-47a6-b8b4-d1845f9706a1',type:dataView),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:client_id,negate:!f,params:(query:'<id>'),type:phrase),query:(match_phrase:(client_id:'<id>'))),('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:event.module,negate:!f,params:(query:google_workspace),type:phrase),query:(match_phrase:(event.module:google_workspace))),('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:user.email,negate:!f,params:(query:'<email>'),type:phrase),query:(match_phrase:(user.email:'<email>')))),hideChart:!f,interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))",
            needsFullLoad: false,
            fields: [
                {
                    placeholder: '<id>',
                    selector: 'input[name="ClientId"]',
                    extractType: 'value',
                },
                {
                    placeholder: '<email>',
                    selector: '[data-testid="alert-table-container"] .MuiTableBody-root .MuiTableRow-root .MuiTableCell-root:nth-child(7) span',
                    extractType: 'textContent',
                },
            ],
            resolutions: {
                escalate: [
                    {
                        client_id: 'default',
                        narrative: async (row) => {
                            const timestamp = row.querySelector('.MuiTableCell-root:nth-child(3) span')?.textContent.trim() || '';
                            const email = row.querySelector('.MuiTableCell-root:nth-child(7) span')?.textContent.trim() || '';
                            const sourceIp = row.querySelector('.MuiTableCell-root:nth-child(9) span')?.textContent.trim() || '';
                            let location = 'Unknown';
                            let isp = 'Unknown';
                            if (sourceIp) {
                                const ipData = await queryIPInfo(sourceIp);
                                location = ipData.location;
                                isp = ipData.isp;
                            }
                            return `GSuite - Unapproved Foreign Country Login\n\nTimestamp: ${timestamp} EST\nAccount: ${email}\nSource IP: ${sourceIp}\nLocation: ${location}\nISP: ${isp}\n\nPlease confirm this action`;
                        },
                        autosave: false,
                        sendEmail: true,
                    },
                ],
                closeBenign: [
                    {
                        client_id: 'default',
                        narrative: (row) => {
                            const sourceIp = row.querySelector('.MuiTableCell-root:nth-child(9) span')?.textContent.trim() || '';
                            return `Closing as benign, IP ${sourceIp} is clean and client previously confirmed this location for the user.`;
                        },
                        autosave: false,
                        status: 'Closed',
                    },
                ],
            },
        },
        {
            name: 'GSuite - Rare Login',
            elasticLink:
                "https://siem.agileblue.com/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-7d%2Fd,to:now))&_a=(columns:!(source.ip,source.geo.region_name,source.as.organization.name),dataSource:(dataViewId:'18e3ccea-a179-47a6-b8b4-d1845f9706a1',type:dataView),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:event.module,negate:!f,params:(query:google_workspace),type:phrase),query:(match_phrase:(event.module:google_workspace))),('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:event.action,negate:!f,params:(query:login_success),type:phrase),query:(match_phrase:(event.action:login_success)))),hideChart:!f,interval:auto,query:(language:kuery,query:'client_id:<id>%20and%20user.email:<email>'),sort:!(!('@timestamp',desc)))",
            needsFullLoad: false,
            fields: [
                {
                    placeholder: '<id>',
                    selector: 'input[name="ClientId"]',
                    extractType: 'value',
                },
                {
                    placeholder: '<email>',
                    selector: '[data-testid="alert-table-container"] .MuiTableBody-root .MuiTableRow-root .MuiTableCell-root:nth-child(7) span',
                    extractType: 'textContent',
                },
            ],
            resolutions: {
                escalate: [
                    {
                        client_id: 'default',
                        narrative: async (row) => {
                            const timestamp = row.querySelector('.MuiTableCell-root:nth-child(3) span')?.textContent.trim() || '';
                            const email = row.querySelector('.MuiTableCell-root:nth-child(7) span')?.textContent.trim() || '';
                            const sourceIp = row.querySelector('.MuiTableCell-root:nth-child(9) span')?.textContent.trim() || '';
                            let location = 'Unknown';
                            let isp = 'Unknown';
                            if (sourceIp) {
                                const ipData = await queryIPInfo(sourceIp);
                                location = ipData.location;
                                isp = ipData.isp;
                            }
                            return `GSuite - Rare Login\n\nTimestamp: ${timestamp} EST\nAccount: ${email}\nSource IP: ${sourceIp}\nLocation: ${location}\nISP: ${isp}\n\nPlease confirm this action`;
                        },
                        autosave: true,
                        sendEmail: true,
                    },
                ],
                closeBenign: [
                    {
                        client_id: 'default',
                        narrative: (row) => {
                            const sourceIp = row.querySelector('.MuiTableCell-root:nth-child(9) span')?.textContent.trim() || '';
                            return `Closing as benign, confirmed that this is not suspicious activity and that the IP ${sourceIp} has a clean reputation.\nLogin location is consistent with user's historical activity and is located near the client.`;
                        },
                        autosave: true,
                        status: 'Closed',
                    },
                ],
            },
        },
        {
            name: 'Server Agent Unresponsive',
            elasticLinkDeviceName:
                "https://siem.agileblue.com/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-7d%2Fd,to:now))&_a=(columns:!(event.action,host.name,event.ingested),dataSource:(dataViewId:'18e3ccea-a179-47a6-b8b4-d1845f9706a1',type:dataView),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:client_id,negate:!f,params:(query:<id>),type:phrase),query:(match_phrase:(client_id:<id>))),('$state':(store:appState),meta:(alias:!n,disabled:!f,field:host.name,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:host.name,negate:!f,params:(query:<device>),type:phrase),query:(match_phrase:(host.name:<device>)))),hideChart:!f,interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))",
            elasticLinkIp:
                "https://siem.agileblue.com/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-7d%2Fd,to:now))&_a=(columns:!(event.action,source.ip,event.ingested),dataSource:(dataViewId:'18e3ccea-a179-47a6-b8b4-d1845f9706a1',type:dataView),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:client_id,negate:!f,params:(query:<id>),type:phrase),query:(match_phrase:(client_id:<id>))),('$state':(store:appState),meta:(alias:!n,disabled:!f,field:source.ip,index:'9079f5b2-b472-46f0-ba7e-fe1f7fddf607',key:source.ip,negate:!f,params:(query:<device>),type:phrase),query:(match_phrase:(source.ip:<device>)))),hideChart:!f,interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))",
            needsFullLoad: false,
            fields: [
                {
                    placeholder: '<id>',
                    selector: 'input[name="ClientId"]',
                    extractType: 'value',
                },
                {
                    placeholder: '<device>',
                    selector: '[data-testid="alert-table-container"] .MuiTableBody-root .MuiTableRow-root .MuiTableCell-root:nth-child(5) a div div',
                    extractType: 'textContent',
                },
            ],
            resolutions: {
                escalate: [
                    {
                        client_id: 'default',
                        narrative: 'Escalated to audit cases team for further investigation of server agent unresponsiveness.',
                        autosave: false,
                        sendEmail: false,
                    },
                ],
                closeBenign: [
                    {
                        client_id: ['581', '582', '583', '584', '585', '586', '587', '588', '589', '590', '591', '592', '593', '595', '596', '597', '602', '603', '604', '605', '606', '607', '608', '609', '610', '611', '612', '613', '614', '615', '616', '617', '618'],
                        narrative: (row) => {
                            const device = row.querySelector('.MuiTableCell-root:nth-child(5) a div div')?.textContent.trim() || 'Unknown';
                            return `Closing as benign per client agreement. Device ${device} matches known "pos" or "server" naming convention and can be ignored for this alert.`;
                        },
                        autosave: true,
                        status: 'Closed',
                    },
                    {
                        client_id: 'default',
                        narrative: 'Closing as false-positive, confirmed that logs are still being ingested in Elastic for the server.\nLast Log Time: \nLast Log Ingested: ',
                        autosave: false,
                        status: 'Closed',
                    },
                ],
            },
        },
    ];

    // Utility function to extract a field value from the case page DOM
    function getFieldValue(field, row) {
        try {
            const element = field.selector.includes('alert-table-container') ? row.querySelector(field.selector) : document.querySelector(field.selector);
            if (!element) {
                console.error(`Selector not found for field ${field.placeholder}: ${field.selector}`);
                return null;
            }
            const value = field.extractType === 'textContent' ? element.textContent.trim() : element[field.extractType];
            console.log(`Extracted value for ${field.placeholder}:`, value);
            return value;
        } catch (error) {
            console.error(`Error extracting field ${field.placeholder}:`, error);
            return null;
        }
    }

    // Function to check if case is closed (Benign, Malicious, or Waiting for Client)
    function isCaseClosed() {
        const statusElement = document.querySelector('.MuiSelect-root.MuiSelect-select, [aria-label="Status"] div.MuiSelect-select');
        if (!statusElement) {
            console.log('Case status element not found. Selectors tried: .MuiSelect-root.MuiSelect-select, [aria-label="Status"] div.MuiSelect-select');
            return false;
        }
        const status = statusElement.textContent.trim().toLowerCase();
        console.log('Current case status:', status);
        return ['benign', 'malicious', 'waiting for client'].includes(status);
    }

    // Generic function to submit a narrative (used for both assignment and resolutions)
    function submitNarrativeGeneric(narrative, status, autosave, sendEmail, row, callback) {
        console.log('Starting narrative submission at', new Date().toISOString());

        // Resolve narrative if it's a function
        const resolvedNarrative = typeof narrative === 'function' ? narrative(row) : narrative;

        // Check if narrative form is already open
        const textBox = document.querySelector('textarea[name="Notes"]');
        const statusLabel = document.querySelector('label[for="Status"]');
        const dropdown = statusLabel?.closest('div.MuiFormControl-root')?.querySelector('div.MuiSelect-select[role="button"][aria-haspopup="listbox"]');
        const submitButton = document.querySelector('button[aria-label="Save"]');

        if (textBox && dropdown && submitButton) {
            console.log('Narrative form already open, skipping Add Narrative button click.');
        } else {
            // Step 1: Click "Add Narrative" button
            const addNarrativeBtn = document.querySelector('button.MuiButton-outlinedSecondary');
            if (!addNarrativeBtn) {
                console.error('Add Narrative button not found. Selector used: button.MuiButton-outlinedSecondary');
                alert('Error: Add Narrative button not found.');
                return;
            }
            addNarrativeBtn.dispatchEvent(new MouseEvent('click', { bubbles: true }));
            console.log('Add Narrative button clicked');
        }

        // Step 2: Wait for form elements to load
        let attempts = 0;
        const maxAttempts = 20; // ~10 seconds
        const formCheckInterval = setInterval(() => {
            attempts++;
            console.log(`Checking form elements, attempt ${attempts}`);

            // Step 3: Find form elements
            const textBox = document.querySelector('textarea[name="Notes"]');
            const statusLabel = document.querySelector('label[for="Status"]');
            const dropdown = statusLabel?.closest('div.MuiFormControl-root')?.querySelector('div.MuiSelect-select[role="button"][aria-haspopup="listbox"]');
            const submitButton = document.querySelector('button[aria-label="Save"]');

            console.log('Form elements status:', {
                textBox: !!textBox,
                statusLabel: !!statusLabel,
                dropdown: !!dropdown,
                submitButton: !!submitButton,
            });

            if (textBox && dropdown && submitButton) {
                clearInterval(formCheckInterval);

                // Step 4: Fill text box and update React state
                try {
                    const setValue = (element, value) => {
                        const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
                        const inputEvent = new Event('input', { bubbles: true });
                        const changeEvent = new Event('change', { bubbles: true });
                        nativeInputValueSetter.call(element, value);
                        element.dispatchEvent(inputEvent);
                        element.dispatchEvent(changeEvent);
                        element.dispatchEvent(new Event('focus', { bubbles: true }));
                        element.dispatchEvent(new Event('blur', { bubbles: true }));
                    };
                    setValue(textBox, resolvedNarrative);
                    console.log('Text box filled with narrative:', resolvedNarrative);
                } catch (error) {
                    console.error('Error setting text box value:', error);
                    alert('Error: Failed to set Notes field.');
                    return;
                }

                // Step 5: Set status if provided
                if (status) {
                    dropdown.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                    dropdown.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                    console.log('Dropdown opened');

                    setTimeout(() => {
                        const statusOption = document.querySelector(`li.MuiMenuItem-root[data-value="${status}"]`);
                        if (statusOption) {
                            statusOption.dispatchEvent(new MouseEvent('click', { bubbles: true }));
                            console.log(`Dropdown set to ${status}`);
                        } else {
                            console.error(`Status option not found: ${status}`);
                            alert(`Error: ${status} option not found in dropdown.`);
                            return;
                        }

                        // Step 6: Submit if autosave is true
                        if (autosave) {
                            setTimeout(() => {
                                submitButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
                                console.log('Save Narrative button clicked');
                                if (sendEmail) {
                                    setTimeout(sendEmailAndUpdateStatus, 1000);
                                }
                                if (callback) callback();
                            }, 500);
                        } else {
                            console.log('Autosave disabled, waiting for manual save');
                            if (callback) callback();
                        }
                    }, 1000);
                } else if (autosave) {
                    setTimeout(() => {
                        submitButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
                        console.log('Save Narrative button clicked');
                        if (sendEmail) {
                            setTimeout(sendEmailAndUpdateStatus, 1000);
                        }
                        if (callback) callback();
                    }, 500);
                } else {
                    console.log('Autosave disabled, waiting for manual save');
                    if (callback) callback();
                }
            } else if (attempts >= maxAttempts) {
                console.error('Max attempts reached, form elements not found:', {
                    textBox: !!textBox,
                    dropdown: !!dropdown,
                    submitButton: !!submitButton,
                });
                clearInterval(formCheckInterval);
                alert('Error: Form elements not found after 10 seconds.');
            }
        }, 500);
    }

    // Function to send email and update case status
    function sendEmailAndUpdateStatus() {
        console.log('Starting email sending and status update at', new Date().toISOString());

        // Step 1: Click "Create Email" button
        const createEmailBtn = document.querySelector('button.MuiButton-outlined[style*="color: rgb(255, 255, 255)"]');
        if (!createEmailBtn) {
            console.error('Create Email button not found. Selector used: button.MuiButton-outlined[style*="color: rgb(255, 255, 255)"]');
            alert('Error: Create Email button not found.');
            return;
        }
        createEmailBtn.dispatchEvent(new MouseEvent('click', { bubbles: true }));
        console.log('Create Email button clicked');

        // Step 2: Wait for Send button to appear in the dialog
        let attempts = 0;
        const maxAttempts = 20; // ~12 seconds
        const emailCheckInterval = setInterval(() => {
            attempts++;
            console.log(`Checking for Send button, attempt ${attempts}`);

            // Scope to the dialog
            const dialog = document.querySelector('.MuiDialog-root');
            if (!dialog) {
                console.log('Dialog not found.');
                if (attempts >= maxAttempts) {
                    console.error('Max attempts reached, dialog not found.');
                    clearInterval(emailCheckInterval);
                    alert('Error: Email dialog not found after 12 seconds.');
                }
                return;
            }

            // Find the Send button within the dialog's actions
            const sendButton = dialog.querySelector('.MuiDialogActions-root button.MuiButton-outlinedSecondary span.MuiButton-label');
            if (sendButton && sendButton.textContent.trim() === 'Send') {
                clearInterval(emailCheckInterval);
                const button = sendButton.closest('button');
                button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
                console.log('Send button clicked');

                // Step 3: Update case status to Waiting for Client
                const statusDropdown = document.querySelector('.MuiSelect-root.MuiSelect-select');
                if (!statusDropdown) {
                    console.error('Case status dropdown not found for update.');
                    alert('Error: Case status dropdown not found.');
                    return;
                }
                statusDropdown.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                statusDropdown.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                console.log('Case status dropdown opened');

                setTimeout(() => {
                    const waitingOption = document.querySelector('li.MuiMenuItem-root[data-value="13"]');
                    if (waitingOption) {
                        waitingOption.dispatchEvent(new MouseEvent('click', { bubbles: true }));
                        console.log('Case status set to Waiting for Client');
                    } else {
                        console.error('Waiting for Client option not found. Selector used: li.MuiMenuItem-root[data-value="13"]');
                        alert('Error: Waiting for Client option not found in dropdown.');
                        return;
                    }

                    // Step 4: Toggle New Alerts switch
                    const newAlertsToggle = document.querySelector('input.MuiSwitch-input[type="checkbox"]');
                    if (!newAlertsToggle) {
                        console.error('New Alerts toggle not found.');
                        alert('Error: New Alerts toggle not found.');
                        return;
                    }
                    if (!newAlertsToggle.unchecked) {
                        newAlertsToggle.dispatchEvent(new MouseEvent('click', { bubbles: true }));
                        console.log('New Alerts toggle disabled');
                    } else {
                        console.log('New Alerts toggle already disabled');
                    }
                }, 1000);
            } else if (attempts >= maxAttempts) {
                console.error('Max attempts reached, Send button not found. Found elements:', {
                    dialog: !!dialog,
                    sendButton: sendButton ? sendButton.textContent : 'not found',
                });
                clearInterval(emailCheckInterval);
                alert('Error: Send button not found after 12 seconds.');
            }
        }, 600);
    }

    // Function to add buttons (investigate, resolution, and assignment)
    function addButtons(abbreviatedName) {
        // Check if case is closed
        if (isCaseClosed()) {
            console.log('Case is closed (Benign, Malicious, or Waiting for Client), removing resolution buttons and skipping addition.');
            // Remove existing resolution buttons
            const escalateButton = document.querySelector('#escalateButton');
            const closeBenignButton = document.querySelector('#closeBenignButton');
            if (escalateButton) {
                escalateButton.remove();
                console.log('Removed Escalate button');
            }
            if (closeBenignButton) {
                closeBenignButton.remove();
                console.log('Removed Close as Benign button');
            }
            return false;
        }

        // Find all alert rows
        const rows = document.querySelectorAll('[data-testid="alert-table-container"] .MuiTableBody-root .MuiTableRow-root');
        if (!rows.length) {
            console.log('No alert rows found.');
            return false;
        }

        let hasSupportedRule = false;
        const fieldValues = {};

        rows.forEach((row) => {
            // Find rule name cell (4th column)
            const cells = row.querySelectorAll('.MuiTableCell-root');
            const nameCell = cells[3];
            if (!nameCell) {
                console.log('Rule name cell not found in row.');
                return;
            }

            // Extract rule name
            const ruleElement = nameCell.querySelector('span');
            const ruleName = ruleElement ? ruleElement.textContent.trim() : null;
            if (!ruleName) {
                console.log('Could not extract rule name from cell.');
                return;
            }
            console.log('Found alert with rule name:', ruleName);

            // Find matching rule
            const rule = rules.find((r) => r.name === ruleName);
            if (!rule) {
                console.log('Rule not supported:', ruleName);
                return;
            }

            hasSupportedRule = true;

            // Extract fields for Elastic URL
            let allFieldsFound = true;
            fieldValues[ruleName] = fieldValues[ruleName] || {};
            for (const field of rule.fields) {
                const value = getFieldValue(field, row);
                if (value !== null && value !== undefined) {
                    fieldValues[ruleName][field.placeholder] = value;
                } else {
                    console.error(`Failed to extract field ${field.placeholder} for rule ${ruleName}`);
                    allFieldsFound = false;
                }
            }

            if (!allFieldsFound) {
                console.error('Missing required fields for rule:', ruleName);
                return;
            }

            // Determine which Elastic link to use
            let elasticUrl;
            const deviceValue = fieldValues[ruleName]['<device>'] || '';
            const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(deviceValue);
            if (isIpAddress && rule.elasticLinkIp) {
                elasticUrl = rule.elasticLinkIp;
                console.log('Device is an IP address, using elasticLinkIp');
            } else if (rule.elasticLinkDeviceName) {
                elasticUrl = rule.elasticLinkDeviceName;
                console.log('Device is a name, using elasticLinkDeviceName');
            } else {
                elasticUrl = rule.elasticLink || '';
                console.log('Using default elasticLink');
            }

            if (!elasticUrl) {
                console.error('No valid Elastic URL defined for rule:', ruleName);
                return;
            }

            // Generate Elastic URL
            for (const [placeholder, value] of Object.entries(fieldValues[ruleName])) {
                elasticUrl = elasticUrl.replaceAll(placeholder, encodeURIComponent(value));
            }
            console.log('Generated Elastic URL:', elasticUrl);

            // Prevent duplicate investigate button
            if (nameCell.querySelector('.investigateElasticButton')) {
                console.log('Investigate button already added for alert:', ruleName);
                return;
            }

            // Add investigate button *before* the span to maintain order
            const investigateButton = document.createElement('button');
            investigateButton.className = 'investigateElasticButton';
            investigateButton.textContent = 'Investigate in Elastic';
            investigateButton.onclick = () => {
                console.log('Investigate button clicked, opening URL:', elasticUrl);
                window.open(elasticUrl, '_blank');
            };
            nameCell.insertBefore(investigateButton, ruleElement); // Insert before the span
            console.log('Investigate button added for alert:', ruleName);

            // Store rule name and client_id for narrative generation
            row.dataset.ruleName = ruleName;
            row.dataset.clientId = fieldValues[ruleName]['<id>'] || '';
        });

        // Add resolution buttons only if case is assigned to the user
        if (hasSupportedRule) {
            // Check assignment
            const assignmentInput = document.querySelector('input.MuiFilledInput-input');
            const isAssignedToMe = assignmentInput && assignmentInput.value === abbreviatedName;
            console.log('Is case assigned to user?', isAssignedToMe, 'Expected name:', abbreviatedName);

            if (isAssignedToMe) {
                // Prevent duplicate resolution buttons
                if (document.querySelector('#escalateButton') || document.querySelector('#closeBenignButton')) {
                    console.log('Resolution buttons already added.');
                    return true;
                }

                // Escalate button
                const escalateButton = document.createElement('button');
                escalateButton.id = 'escalateButton';
                escalateButton.className = 'resolutionButton';
                escalateButton.innerHTML = `
                    <svg class="MuiSvgIcon-root" focusable="false" viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"></path>
                    </svg>
                    Escalate
                `;
                escalateButton.onclick = async () => {
                    // Re-query rows to ensure fresh DOM references
                    const rows = document.querySelectorAll('[data-testid="alert-table-container"] .MuiTableBody-root .MuiTableRow-root');
                    const row = Array.from(rows).find((r) => r.dataset.ruleName && rules.some((rule) => rule.name === r.dataset.ruleName && rule.resolutions?.escalate));
                    if (!row) {
                        console.error('No valid row found for escalate');
                        alert('Error: No supported alert found for escalation.');
                        return;
                    }
                    const rule = rules.find((r) => r.name === row.dataset.ruleName);
                    const clientId = row.dataset.clientId || '';
                    const resolution = rule.resolutions.escalate.find((c) =>
                        Array.isArray(c.client_id) ? c.client_id.includes(clientId) : c.client_id === clientId
                    ) || rule.resolutions.escalate.find((c) => c.client_id === 'default');
                    if (!resolution) {
                        console.error('No resolution found for escalate, client_id:', clientId);
                        alert('Error: No escalation configuration found for this client.');
                        return;
                    }
                    const narrative = typeof resolution.narrative === 'function' ? await resolution.narrative(row) : resolution.narrative;
                    console.log('Escalate button clicked for rule:', rule.name, 'client_id:', clientId);
                    submitNarrativeGeneric(narrative, null, resolution.autosave, resolution.sendEmail || false, row);
                };
                document.body.appendChild(escalateButton);
                console.log('Escalate button added');

                // Close Benign button
                const closeBenignButton = document.createElement('button');
                closeBenignButton.id = 'closeBenignButton';
                closeBenignButton.className = 'resolutionButton';
                closeBenignButton.innerHTML = `
                    <svg class="MuiSvgIcon-root" focusable="false" viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"></path>
                    </svg>
                    Close as Benign
                `;
                closeBenignButton.onclick = async () => {
                    // Re-query rows to ensure fresh DOM references
                    const rows = document.querySelectorAll('[data-testid="alert-table-container"] .MuiTableBody-root .MuiTableRow-root');
                    const row = Array.from(rows).find((r) => r.dataset.ruleName && rules.some((rule) => rule.name === r.dataset.ruleName && rule.resolutions?.closeBenign));
                    if (!row) {
                        console.error('No valid row found for closeBenign');
                        alert('Error: No supported alert found for closing as benign.');
                        return;
                    }
                    const rule = rules.find((r) => r.name === row.dataset.ruleName);
                    const clientId = row.dataset.clientId || '';
                    const resolution = rule.resolutions.closeBenign.find((c) =>
                        Array.isArray(c.client_id) ? c.client_id.includes(clientId) : c.client_id === clientId
                    ) || rule.resolutions.closeBenign.find((c) => c.client_id === 'default');
                    if (!resolution) {
                        console.error('No resolution found for closeBenign, client_id:', clientId);
                        alert('Error: No close benign configuration found for this client.');
                        return;
                    }
                    const narrative = typeof resolution.narrative === 'function' ? await resolution.narrative(row) : resolution.narrative;
                    console.log('Close Benign button clicked for rule:', rule.name, 'client_id:', clientId);
                    submitNarrativeGeneric(narrative, resolution.status, resolution.autosave, false, row);
                };
                document.body.appendChild(closeBenignButton);
                console.log('Close as Benign button added');
            } else {
                console.log('Case not assigned to user, skipping resolution buttons.');
            }
        }

        return hasSupportedRule;
    }

    // Debounce function to limit MutationObserver frequency
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Function to find user name with retry
    function findUserName(callback) {
        console.log('Starting user name search at', new Date().toISOString());
        let attempts = 0;
        const maxAttempts = 20; // ~10 seconds
        const checkInterval = setInterval(() => {
            attempts++;
            console.log(`Checking for user name element, attempt ${attempts} at`, new Date().toISOString());
            const userNameElement = document.querySelector('p.username');
            if (userNameElement) {
                console.log('User name element found');
                clearInterval(checkInterval);
                callback(userNameElement);
            } else if (attempts >= maxAttempts) {
                console.error('Max attempts reached, user name element not found. Selector used: p.username');
                clearInterval(checkInterval);
                alert('Error: User name element not found after 10 seconds.');
            }
        }, 500);
    }

    // Process user name and initialize case assignment
    findUserName((userNameElement) => {
        const fullName = userNameElement.textContent.trim();
        console.log('Found full name:', fullName);

        const nameParts = fullName.split(' ');
        console.log('Name parts:', nameParts);
        if (nameParts.length < 2) {
            console.error('Unable to parse user name. Expected at least two parts, got:', nameParts);
            return;
        }
        const abbreviatedName = `${nameParts[0][0]}. ${nameParts[1]}`;
        console.log('Constructed abbreviated name:', abbreviatedName);

        // Function to assign the case
        function assignCase() {
            console.log('Starting case assignment for', abbreviatedName, 'at', new Date().toISOString());
            submitNarrativeGeneric(
                'Assigned and beginning investigation.',
                'Investigating',
                true,
                false,
                null,
                () => {
                    console.log('Case assigned, re-checking button visibility');
                    toggleButtonVisibility();
                }
            );
        }

        // Add assign case button
        const assignButton = document.createElement('button');
        assignButton.id = 'assignCaseButton';
        assignButton.innerHTML = `
            <svg class="MuiSvgIcon-root" focusable="false" viewBox="0 0 24 24" aria-hidden="true">
                <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"></path>
            </svg>
            Assign Case to Me
        `;
        assignButton.addEventListener('click', assignCase);
        document.body.appendChild(assignButton);
        console.log('Assign Case button appended to document body');

        // Function to toggle button visibility and manage resolution buttons
        function toggleButtonVisibility() {
            console.log('Checking button visibility at', new Date().toISOString());
            const assignmentInput = document.querySelector('input.MuiFilledInput-input');
            console.log('Assignment input found:', !!assignmentInput, 'Value:', assignmentInput?.value);
            const isAssignedToMe = assignmentInput && assignmentInput.value === abbreviatedName;
            console.log('Is case assigned to user?', isAssignedToMe, 'Expected name:', abbreviatedName);

            // Check if case is closed
            if (isCaseClosed()) {
                console.log('Case is closed, ensuring resolution buttons are removed');
                const escalateButton = document.querySelector('#escalateButton');
                const closeBenignButton = document.querySelector('#closeBenignButton');
                if (escalateButton) {
                    escalateButton.remove();
                    console.log('Removed Escalate button due to closed case');
                }
                if (closeBenignButton) {
                    closeBenignButton.remove();
                    console.log('Removed Close as Benign button due to closed case');
                }
            }

            // Toggle assign button
            if (isAssignedToMe) {
                assignButton.classList.add('hidden');
                console.log(`Case assigned to ${abbreviatedName}, hiding assign button`);
            } else {
                assignButton.classList.remove('hidden');
                console.log(`Case not assigned to ${abbreviatedName}, showing assign button`);
            }
            // Add or update resolution buttons based on assignment
            addButtons(abbreviatedName);
        }

        // Retry mechanism to wait for dynamic content
        function checkForAlerts(attempt = 1, maxAttempts = 40, interval = 500) {
            console.log(`Checking for alerts, attempt ${attempt}/${maxAttempts}`);
            const alertsSection = document.querySelector('[data-testid="alert-table-container"]');
            if (alertsSection) {
                console.log('Alerts section found, adding buttons...');
                if (addButtons(abbreviatedName)) {
                    console.log('Supported rule found, buttons added.');
                } else {
                    console.log('No supported rules found or case is closed.');
                }
            } else if (attempt < maxAttempts) {
                console.log('Alerts section not found, scheduling retry...');
                setTimeout(() => checkForAlerts(attempt + 1, maxAttempts, interval), interval);
            } else {
                console.error('Max attempts reached, no alerts section found.');
            }
            // Always check assignment button visibility
            toggleButtonVisibility();
        }

        // Observe DOM changes to handle dynamic updates with debouncing
        const debouncedAddButtons = debounce(() => {
            console.log('DOM change detected, re-checking for alerts and visibility...');
            addButtons(abbreviatedName);
            toggleButtonVisibility();
        }, 500);

        // Target the status dropdown's parent container for observation
        const statusContainer = document.querySelector('.MuiFormControl-root:has(.MuiSelect-root.MuiSelect-select)') || document.body;
        const observer = new MutationObserver(debouncedAddButtons);
        observer.observe(statusContainer, { childList: true, subtree: true });
        console.log('MutationObserver set up on:', statusContainer === document.body ? 'document.body' : 'status container');

        // Start the initial check
        console.log('Starting alerts and assignment check');
        checkForAlerts();

        // Re-check on navigation (for single-page apps)
        window.addEventListener('popstate', () => {
            console.log('Navigation detected, checking button visibility at', new Date().toISOString());
            toggleButtonVisibility();
        });
    });
})();