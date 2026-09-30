import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

# Example data (replace with your own DataFrame)
data = {
    'Power': [49, 47, 13, 8],
    'Echo Dot': [3, 45, 0, 0],
    'T-Echo Dot': [4, 45, 0, 0],
    'Wemo Plug': [22, 25, 0, 1],
    'D-Link': [12, 0, 0, 12],
    'LG TV': [9, 9, 0, 0],
    'Android': [876, 791, 80, 0],
    'Alexa': [1, 510, 0, 0],
    'T-Philips Hub': [0, 83, 0, 0],
    'Samsung TV': [0, 1, 0, 0],
    'UK': [4, 4, 0, 0],
    'Amcrest Camera': [40, 0, 0, 0],
    'Zmodo Doorbell': [4, 4, 0, 0],
    'Fire TV': [2, 5, 0, 1],

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
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.tight_layout(pad=.01)
# Save the figure if needed
plt.savefig('./figures/heatmap_event.png', dpi=300,  bbox_inches='tight')
plt.show()