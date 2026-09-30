import pandas as pd

# ---- CONFIG ----
#input_file = "~/update_traffic/controlled/entropy/sony_tv.csv"        # Your original CSV file
#output_file = "~/update_traffic/controlled/entropy/sony_formatted.csv"  # Output file to save
input_file = "~/update_traffic/controlled/entropy/tapo.csv"        # Your original CSV file
output_file = "~/update_traffic/controlled/entropy/_formatted.csv"  # Output file to save





# ---- READ INPUT CSV ----
df = pd.read_csv(input_file)

# Create an index starting from 1
df['index'] = range(1, len(df) + 1)

# ---- FORMAT THE ENTROPY COLUMNS ----
df['entropy_shannon'] = df.apply(
    lambda row: f"({row['index']},{row['entropy_shannon']})", axis=1)

df['entropy_renyi'] = df.apply(
    lambda row: f"({row['index']},{row['entropy_renyi']})", axis=1)

df['entropy_tsallis'] = df.apply(
    lambda row: f"({row['index']},{row['entropy_tsallis']})", axis=1)

# ---- SELECT ONLY THE THREE FORMATTED COLUMNS ----
output_df = df[['entropy_shannon', 'entropy_renyi', 'entropy_tsallis']]

# ---- SAVE TO NEW CSV ----
output_df.to_csv(output_file, index=False)

print(f"Saved formatted entropy CSV to: {output_file}")




