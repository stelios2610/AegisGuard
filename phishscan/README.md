# PhishScan

Πρόγραμμα για **τον υπολογιστή σας** (Windows / Linux / macOS). Δεν είναι μέρος του FGUARD και δεν χρειάζεται διακομιστή.

Κολλάτε έναν σύνδεσμο ή ένα email. Το πρόγραμμα σας λέει αν μοιάζει με phishing — **χωρίς να ανοίξει τον σύνδεσμο**.

Φτιάχτηκε για την περίπτωση του Outlook / SharePoint: αληθινό `*.sharepoint.com`, αλλά το «αρχείο» λέγεται

> *σας έστειλε ένα ασφαλές μήνυμα. Κάντε κλικ στην επιλογή Λήψη εγγράφου…*

Αυτό περνάει τα φίλτρα γιατί το domain είναι της Microsoft. Το PhishScan κοιτάει το **όνομα του αρχείου**, κρυφούς χαρακτήρες, και αν το κείμενο του link ταιριάζει με τον πραγματικό προορισμό.

## Εγκατάσταση στον υπολογιστή

Χρειάζεται μόνο **Python 3.9+** (χωρίς extra πακέτα).

### Windows

1. Εγκαταστήστε Python από https://www.python.org/downloads/
   - Στο installer τσεκάρετε **Add python.exe to PATH**
2. Αντιγράψτε τον φάκελο `phishscan` όπου θέλετε (π.χ. `C:\Tools\phishscan`)
3. Διπλό κλικ στο **`install.bat`** — φτιάχνει συντόμευση στην επιφάνεια εργασίας
4. Ή διπλό κλικ στο **`PhishScan.bat`** για να ανοίξει κατευθείαν το παράθυρο

### Γραμμή εντολών

```bat
python phishscan.py "https://…"
python phishscan.py email.eml
python phishscan.py --gui
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
