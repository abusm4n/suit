import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

# Example data (replace with your own DataFrame)
data = {
    'apple-tv': [0, 11, 0, 0],
    'echo-dot': [0, 4, 4, 0],
    'echoplus': [0, 5, 5, 1],
    'fire-tv': [0, 4, 4, 0],
    'invoke': [0, 10, 0, 0],
    'roku-tv': [0, 4, 0, 0],
    'samsung-tv': [0, 0, 5, 3],
    'thermostat': [0, 6, 0, 0],
    'uncontrol': [0, 21, 14, 0],
    'wink-hub2': [0, 6, 0, 0],
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
plt.savefig('./figures/heatmap_encrypted.png', dpi=300,  bbox_inches='tight')
plt.show()