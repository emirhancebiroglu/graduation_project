import json
s = {
    'median': [2.3978952728, 1.0986122887, 1.3862943611, 0.970951, 11.0, 0.25, 0.1541509655],
    'iqr': [1.7429693051, 0.2876820725, 1.5404450409, 0.964861, 4472.0, 0.28022, 0.4054651081]
}
with open('/home/emirhan/bitirme/models/dos_aggregator_model_scaler.json', 'w') as f:
    json.dump(s, f, indent=2)
print('Created')
