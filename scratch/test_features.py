import sys
sys.path.insert(0, r'c:\Users\Danish\OneDrive\Desktop\All in one')

from services.scam_detector import nlp_analyzer, link_checker, fraud_scorer

# Test NLP keyword analysis
print('=== Testing NLP Keyword Analysis ===')
test_msg = 'Join our exclusive crypto trading group! Guaranteed 30% weekly returns. Act now limited slots.'
a, b, reasons, status = nlp_analyzer.analyze_text(test_msg)
print(f'Engine A (XGBoost/Keyword): {a}')
print(f'Engine B (XLM-RoBERTa): {b}')
print(f'Engine Status: {status}')
print(f'Reasons count: {len(reasons)}')
for r in reasons:
    print(f'  - {r}')

# Test WHOIS domain check
print('\n=== Testing WHOIS Domain Check ===')
risk, r = link_checker.check_links('Visit quickprofit123.xyz for more investment info')
print(f'Link risk: {risk}')
for reason in r:
    print(f'  - {reason}')

# Test fraud scorer
print('\n=== Testing ML/Fraud Scorer ===')
score, color = fraud_scorer.compute_risk(a, risk)
print(f'Final score: {score}, Color: {color}')

print('\n=== All tests complete ===')
