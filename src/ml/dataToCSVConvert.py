import csv
from cwe_examples import cwe_examples  

def export_to_csv(filename="cwe_dataset.csv"):
    # Open the CSV file for writing
    with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["CWE", "Description", "Code"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Loop over your CWE examples dictionary and write each row
        for cwe_id, data in cwe_examples.items():
            writer.writerow({
                "CWE": cwe_id,
                "Description": data["description"],
                "Code": data["code"]
            })

if __name__ == "__main__":
    export_to_csv()
    print("CWE dataset exported to cwe_dataset.csv")
