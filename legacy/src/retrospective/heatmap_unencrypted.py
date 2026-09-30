import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

# Example data (replace with your own DataFrame)
data = {
    'allure-speaker': [0, 0, 6, 0],
    'amcrest-cam': [13, 0, 0, 0],
    'apple-tv': [0, 1, 1, 1],
    'd-link-mov': [6, 0, 0, 6],
    'lg-tv': [10, 12, 0, 0],
    'philips-hub': [0, 509, 0, 0],
    'roku-tv': [0, 0, 76, 0],
    'samsung-tv': [8, 228, 6, 0],
    'uncontrol': [96, 217, 0, 14],
    'wemo-plug': [602, 602, 0, 1],
}
index = ['firmware', 'update', 'software', 'download']
df = pd.DataFrame(data, index=index)

import numpy as np

# Create a custom annotation matrix: show value if > 0, else show empty string
annot = df.map(lambda x: f"{x}" if x != 0 else "")

# Plot with custom annotations
plt.figure(figsize=(7, 4))
sns.heatmap(df, annot=annot, cmap='Blues', fmt='')
#plt.xlabel('IoT Device')
#plt.ylabel('Detected Keyword')
plt.xticks(rotation=45, ha='right', fontsize=12)
plt.tight_layout()
plt.tight_layout(pad=.01)
# Save the figure if needed
plt.savefig('./figures/heatmap_unencrypted.png', dpi=300,  bbox_inches='tight')
plt.show()