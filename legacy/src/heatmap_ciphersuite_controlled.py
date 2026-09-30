
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

# Example data (replace with your own DataFrame)
data = {
    'apple-tv': [9, 4, 7, 0],
    'd-link cam': [9, 4, 7, 1],
    'eufy-cam': [11, 6, 67, 1],
    'fire-tv': [13, 6, 17, 1],
    'homepod': [9, 4, 7, 0],
    'riolink-cam': [9, 6, 11, 1],
    'sony-tv': [8, 6, 46, 1],
    'tapo-c100': [9, 4, 7, 0],
    'tapo-c200': [11, 6, 54, 8],
    'xiaomi-cam': [11, 6, 67, 1],


}
index = ['secure', 'recommended', 'weak', 'insecure']
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
plt.savefig('./figures/heatmap_ciphersuite_controlled.png', dpi=300,  bbox_inches='tight')
plt.show()