import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Load dataset from CSV
dataset = pd.read_csv("./csv/all_base.csv")

# Set the size of the figure
plt.figure(figsize=(7, 3))
sns.set_theme(style="whitegrid")

# Strip plot
sns.stripplot(
    data=dataset,
    x='year',
    y='base',
    hue='type',
    palette={'update_traffic': "#2D48A0", '': '#FFD700'},
    hue_order=['update_traffic', ''],
    dodge=True,
    jitter=True,
    size=8
)

# Customize legend and labels
plt.legend(title='', loc='lower center')
plt.xlabel('')
plt.ylabel('Base Score')

# --- Fix x-axis labels to show 'YY ---
ax = plt.gca()
ticks = ax.get_xticks()
labels = [tick.get_text() for tick in ax.get_xticklabels()]
new_labels = [f"'{year[-2:]}" for year in labels if year]  # ensure non-empty
ax.set_xticks(ticks)
ax.set_xticklabels(new_labels, rotation=45)  # rotate for readability

# Save the plot as a PDF
plt.savefig("./figures/base__plot.pdf", format='pdf', bbox_inches='tight')

# Show the plot
plt.show()
