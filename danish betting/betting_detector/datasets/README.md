# datasets/
# Place your training data here in YOLO format:
#
# datasets/
# ├── images/
# │   ├── train/    ← training images (.jpg, .png)
# │   └── val/      ← validation images
# └── labels/
#     ├── train/    ← YOLO annotation .txt files
#     └── val/
#
# Each label file line: <class_id> <x_center> <y_center> <width> <height>  (normalized 0-1)
#
# Class IDs (see data.yaml):
#   0: 1xbet
#   1: bet365
#   2: parimatch
#   3: stake
#   4: dafabet
#   5: melbet
#   6: betting_slip
#   7: odds_table
#   8: casino_chips
#   9: roulette_table
