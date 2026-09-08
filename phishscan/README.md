# PhishScan

Πρόγραμμα για **τον υπολογιστή σας** (Windows / Linux / macOS). Δεν είναι μέρος του FGUARD και δεν χρειάζεται διακομιστή.

Κολλάτε έναν σύνδεσμο ή ένα email. Το πρόγραμμα σας λέει αν μοιάζει με phishing — **χωρίς να ανοίξει τον σύνδεσμο**.

Φτιάχτηκε για την περίπτωση του Outlook / SharePoint: αληθινό `*.sharepoint.com`, αλλά το «αρχείο» λέγεται

> *σας έστειλε ένα ασφαλές μήνυμα. Κάντε κλικ στην επιλογή Λήψη εγγράφου…*

Αυτό περνάει τα φίλτρα γιατί το domain είναι της Microsoft. Το PhishScan κοιτάει το **όνομα του αρχείου**, κρυφούς χαρακτήρες, και αν το κείμενο του link ταιριάζει με τον πραγματικό προορισμό.

## Εγκατάσταση στον υπολογιστή (Windows)

Διπλό κλικ στο **`PhishScan-Setup.bat`**.

- Δεν χρειάζεται administrator
- Αντιγράφει το πρόγραμμα στο `%LOCALAPPDATA%\Programs\PhishScan`
- Φτιάχνει συντόμευση στην επιφάνεια εργασίας και στο Start Menu
- Απεγκατάσταση από Start Menu → PhishScan → Απεγκατάσταση, ή από Apps & Features

Αν δεν υπάρχει Python 3, ο installer προσπαθεί `winget`. Αλλιώς εγκαταστήστε Python από https://www.python.org/downloads/ (τσεκάρετε **Add python.exe to PATH**) και ξανατρέξτε το Setup.

### Χωρίς installer / γραμμή εντολών

```bat
python phishscan.py --gui
python phishscan.py "https://…"
python phishscan.py email.eml
```

Κωδικοί εξόδου: `0` καθαρό, `1` ύποπτο, `2` phishing.

## Τι εντοπίζει

- Ονόματα αρχείων-οδηγίες («ασφαλές μήνυμα», *secure message*, *click to view*) σε SharePoint / OneDrive / Drive / Dropbox
- Non-breaking space και άλλους αόρατους χαρακτήρες στο path
- HTML/JS αρχεία μοιρασμένα από cloud
- Domain που παριστάνει Microsoft / PayPal / τράπεζες κ.λπ. χωρίς να είναι το επίσημο
- Punycode / ανάμεικτα αλφάβητα στο hostname
- Username στο URL (`microsoft.com@evil…`)
- URL shorteners
- Outlook SafeLinks: ξετυλίγει τον εσωτερικό σύνδεσμο και ελέγχει εκείνον
- HTML όπου το κείμενο λέει `login.microsoftonline.com` αλλά το `href` πάει αλλού

**Δεν** κατεβάζει το PDF, δεν βάζει κωδικούς, δεν μιμείται login σελίδες.

## Τι δεν είναι

Δεν αντικαθιστά antivirus, SPF/DKIM, ούτε το IT. Αν βγει «καθαρό», πάλι μην ανοίγετε ύποπτα αρχεία από αγνώστους. Αν βγει phishing, επιβεβαιώστε τον αποστολέα **τηλεφωνικά**.

## Δοκιμές

```bat
python -m unittest tests.test_analyzer
```
