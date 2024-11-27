<?php
header('Content-Type: application/json');

// Path to the CSV file
$csvFile = 'uploads/suspicious_traffic_log.csv';

// Check if the file exists
if (file_exists($csvFile)) {
    // Load and process the CSV
    $data = [];
    if (($handle = fopen($csvFile, 'r')) !== false) {
        // Read the header (assuming there is a header)
        $header = fgetcsv($handle);

        // Initialize an array to count all vulnerabilities
        $vulnerabilities = [];

        // Process the rows in the CSV
        while (($row = fgetcsv($handle)) !== false) {
            // Example: Assume the 'Reason' column is at index 2 (adjust according to your structure)
            $reason = $row[2]; // Adjust according to your "Reason" column in the CSV

            // Check if the reason already exists in the vulnerabilities array
            if (isset($vulnerabilities[$reason])) {
                $vulnerabilities[$reason]++;
            } else {
                $vulnerabilities[$reason] = 1;
            }
        }

        fclose($handle);

        // Return the data as JSON
        echo json_encode($vulnerabilities);
    }
} else {
    // Return error message if the CSV file is not found
    echo json_encode(['error' => 'CSV file not found.']);
}
?>
