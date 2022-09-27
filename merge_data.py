import json
import os

def write_cve_to_file(new_data, filename):
  # Check if the file exists
  if not os.path.exists(filename):
    # Creates a new file
    with open(filename, 'w') as file:
        pass

  # Write data to file
  with open(filename,'w') as file:
    json.dump(new_data, file, indent = 2)

  print('Done saving {}'.format(filename))
  
# Find all years and divide by 2 groups; 100,000 is max limit
years = os.listdir('review_set')
print('Total years found:', len(years))

# years_sets = [years[:len(years)//2], years[len(years)//2:]]
years_sets = [["1999"],["2000","2001","2002","2003","2004","2005","2006"], ["2007","2008","2009","2010","2011","2012","2013","2014"], ["2015","2016","2017","2018","2019","2020","2021","2022"]]
# print(years_sets)

bulk_import_sets=[[], [], [], []]
count = 0

for i, years_set in enumerate(years_sets):
  # year_set ['1999']
  for year in years_set:
    # cve_group [0xxx, 1xxx]
    for cve_group in os.listdir('review_set/' + year):
      for filename in os.listdir('review_set/' + year + '/' + cve_group):
        with open('review_set/{}/{}/{}'.format(year, cve_group, filename)) as file:
          # Read the CVE Record from file and save it
          file_content = json.load(file)
          count += 1
          print('{} {} {} {}/{}'.format(cve_group, i, count, year, filename)) 
          bulk_import_sets[i].append(file_content)
  
  write_cve_to_file(bulk_import_sets[i], 'merged_dataset{}-{}.json'.format(i, count))
  print('Run {}: Found {} records'.format(i, len(bulk_import_sets[i])))
  