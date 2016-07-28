otx2crits
---------
otx2crits pulls your AlienVault OTX "pulses" and adds them to CRITS. This allows you to select pulses that are interesting to you and import only those pulse.

Within CRITS, it will add the overall pulse as an Event object, then convert and add the indicators as Indicator objects. Once that is complete, it builds relationships between the Event and the Indicators. The result is properly imported data from AlienVault pulses that interest you.

In each event, otx2crits will create a Ticket in the Event object. This ticket contains the pulse id and is used to track whether a specific pulse has been used before.

Installation
------------
Copy config.ini.example to ~/.otx_config or another location of your choosing. Edit the file with your information.

If necessary, add a source to CRITs for AlienVault. To do this:

1. Click the gear symbol in the top left and go to "CRITs Control Panel".
2. Click "Items" then the "Sources" tab.
3. Click "Add SourceAccess" near the top right. Add your source.
4. Go to the "Users" section on the left hand side.
5. For each user, allow the user to use the source.

The final step is to prepare your CRITs vocabulary file. If you use the vanilla CRITs vocabulary, ignore this paragraph. The indicator vocabulary from CRITs must also be correct. If you have changed your CRITs vocabulary, copy your crits/vocabulary/indicators.py to the vocabulary/ directory inside your otx2crits installation. Remove the line that says `from crits.vocabulary.vocab import vocab` and remove all references to `vocab`. For example, `class IndicatorTypes(vocab):` becomes `class IndicatorTypes():`.

Requirements
------------
This was written for python3, but will probably work fine on python2.

CRITS 4 is required. The API for CRITS must be enabled.

Python libraries
- requests
- pycrits from https://github.com/Magicked/pycrits
  - Note: The only difference is allowing pycrits to interface with proxies and verify with the requests library
  - git clone https://github.com/Magicked/pycrits; cd pycrits; python3 setup.py install

Usage
-----
To begin, you must subscribe to interesting pulses on AlienVault OTX. As a starting point, check out https://otx.alienvault.com/user/AlienVault/pulses/ and subscribe to a few.

Once you have otx2crits ready to go, run it for the first time without arguments. If you have a dev CRITs environment set up, test it using that first.

```bash
$ python3 otx2crits.py --dev
```

This will download information from ALL the pulses you subscribe to and enter them into CRITs.

Once you have verified things are working well, feel free to drop the --dev flag. If you want, you can provide the -d flag with a number of days to specify a maximum age of the pulses. Doing this will ensure you don't pull all of your pulses every time.

```bash
# Get pulses that have been modified in the last 14 days
python3 otx2crits.py --dev -d 14
```

Finally, you can set up a cron job to run this script regularly. This will allow you to subscribe to new pulses in AlienVault OTX and they will then be added to CRITs automatically. Yay automation!

Then you can do fancy analysis on relationships!

![crits relationship screenshot](https://magicked.github.io/images/crits_data_map.png)
