import xgboost as xgb
m = xgb.Booster()
m.load_model('/home/emirhan/bitirme/models/bot_client_model.json')
print('num_features:', m.num_features())
print('feature_names:', m.feature_names)
