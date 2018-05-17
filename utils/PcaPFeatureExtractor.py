import numpy as np
import pickle as pickle
from .reader import sessionizer
from .featurizer import extract_features

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

from .training_utils import read_data
from .training_utils import select_features


class PcaPFeatureExtractor:
    def __init__(self, duration, labels=None):
        '''
        Initializes a model with a single hidden layer.  Features are
        aggregated over the time specified by the duration and the hidden
        layer size is a hyperparameter set at initialization.

        Args:
            duration: Time duration to aggregate features for
        '''

        self.duration = duration

        self.means = None
        self.stds = None
        self.feature_list = None
        self.model = None
        self.labels = labels

        self.sessions = None

    def get_x_y(self, data_dir):
        '''
        Trains a single layer model on the data contained in the specified
        directory.  Labels found in the directory are augmented with an
        unknown label.

        Args:
            data_dir: Directory containing the training data
        '''

        print("Reading data")
        # First read the data directory for the features and labels
        X_all, y_all, new_labels = read_data(
                                              data_dir,
                                              duration=self.duration,
                                              labels=self.labels
												)
        self.labels = new_labels
					

