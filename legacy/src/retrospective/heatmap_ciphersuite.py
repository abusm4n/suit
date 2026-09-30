import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

# Example data (replace with your own DataFrame)
data = {
    'amcrest-cam': [6, 6, 46, 1],
    'apple-tv': [9, 6, 11, 1],
    'd-link-mov': [6, 6, 37, 10],
    'echo-plus': [6, 6, 67, 4],
    'fire-tv': [6, 6, 12, 4],
    'lg-tv': [6, 6, 67, 12],
    'philips-hub': [10, 6, 64, 7],
    'roku-tv': [6, 6, 66, 6],
    'samsung-tv': [8, 6, 56, 7],
    'wemo-plug': [0, 0, 12, 1],
    #'Echo Dot': [8, 6, 52, 1],
    # 'Thermostat': [2, 6, 13, 0],
    #'Wink hub2': [8, 6, 67, 1],

 }
index = ['secure', 'recommen', 'weak', 'insecure']
df = pd.DataFrame(data, index=index)

import numpy as np

# Create a custom annotation matrix: show value if > 0, else show empty string
annot = df.map(lambda x: f"{x}" if x != 0 else "")

# Plot with custom annotations
plt.figure(figsize=(7, 4))
sns.heatmap(df, annot=annot, cmap='Blues', fmt='')
#plt.xlabel('IoT Device')
#plt.ylabel('Detected Keyword')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.tight_layout(pad=.01)
# Save the figure if needed
plt.savefig('./figures/heatmap_ciphersuite.png', dpi=300,  bbox_inches='tight')
plt.show()