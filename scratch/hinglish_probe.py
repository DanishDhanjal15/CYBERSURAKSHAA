import sys, os
BASE = r'C:\Users\Danish\OneDrive\Desktop\All in one'
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, 'evaluation'))
sys.path.insert(0, os.path.join(BASE, 'danish betting', 'betting_detector'))

from metrics import use_utf8_stdout
use_utf8_stdout()

from models.text_classifier import TextClassifier

c = TextClassifier()
THRESH = 0.4

BETTING = [
    'satta matka result aaj ka open close dekho',
    'teen patti khelo aur asli paisa jeeto',
    'cricket satta rate live bhav yahan',
    'lagao aur jeeto instant withdrawal upi se',
    'सट्टा मटका का रिजल्ट आज यहाँ देखें',
    'आज का फिक्स मैच पक्का जीत टिप्स लो',
    'तीन पत्ती खेलो और असली पैसा जीतो',
]
BENIGN = [
    'india ne kal ka match jeet liya team ne accha khela',
    'kohli ne shandaar century lagayi kal ke match me',
    'fantasy team banao aur doston ke saath khelo',
    'diwali sale me mobile phones par bhaari discount',
    'bijli ka bill online bhar diya receipt aa gayi',
    'भारत ने कल का मैच जीत लिया',
    'दीवाली सेल में मोबाइल फोन पर छूट',
    'सरकार ने सट्टेबाजी के विज्ञापनों पर रोक लगाई है',
]

print('--- Hinglish / Devanagari BETTING  (want >= %.1f) ---' % THRESH)
ok = 0
for t in BETTING:
    p = c.classify(t).betting_probability
    hit = p >= THRESH
    ok += hit
    print('  %.3f  %s  %s' % (p, 'OK  ' if hit else 'MISS', t[:54]))
print('  caught %d/%d' % (ok, len(BETTING)))

print()
print('--- Hinglish / Devanagari BENIGN  (want < %.1f) ---' % THRESH)
clean = 0
for t in BENIGN:
    p = c.classify(t).betting_probability
    good = p < THRESH
    clean += good
    print('  %.3f  %s  %s' % (p, 'OK  ' if good else 'FALSE ALARM', t[:54]))
print('  left alone %d/%d' % (clean, len(BENIGN)))
