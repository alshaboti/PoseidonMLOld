

import sys
import json
from utils.PcaPFeatureExtractor import PcaPFeatureExtractor

if __name__ == '__main__':
    # Load model params from config
    with open('my_config.json') as config_file:
        config = json.load(config_file)

        duration = config['duration']
        labels = config['labels']
        sourceIdentifier = config['source identifier']

    # Get the data directory
    if len(sys.argv) < 2:
        data_dir = "pcaps"
    else:
        data_dir = sys.argv[1]

    extractor = PcaPFeatureExtractor(
                        duration=duration,
                        labels=labels
                       )

    extractor.get_x_y(data_dir)		