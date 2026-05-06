import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import tensorflow as tf
import numpy as np
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

model_path = ROOT / 'models' / 'fine_tuned_lstm_model_v5.h5'
out_path   = ROOT / 'models' / 'fine_tuned_lstm_model_v5.tflite'

model = tf.keras.models.load_model(model_path)

# unroll=True ile TFLite'a çevir
run_model = tf.function(lambda x: model(x))
concrete_func = run_model.get_concrete_function(
    tf.TensorSpec([1, 1, 11], tf.float32))

converter = tf.lite.TFLiteConverter.from_concrete_functions([concrete_func])
tflite_model = converter.convert()

with open(out_path, 'wb') as f:
    f.write(tflite_model)
print(f'Kaydedildi: {out_path} ({len(tflite_model)} bytes)')