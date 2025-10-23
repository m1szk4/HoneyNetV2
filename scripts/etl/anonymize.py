#!/usr/bin/env python3
"""
IP Anonymization Script for IoT Honeypot
Purpose: Anonymize any remaining plain-text IPs in ClickHouse database
Usage: python anonymize.py [--dry-run]
"""

import os
import sys
import hmac
import hashlib
import argparse
from datetime import datetime
import clickhouse_connect

# Configuration
CLICKHOUSE_HOST = os.getenv('CLICKHOUSE_HOST', 'localhost')
CLICKHOUSE_PORT = int(os.getenv('CLICKHOUSE_PORT', '8123'))
CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER', 'default')
CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD', '')
CLICKHOUSE_DATABASE = 'honeynet'
SALT_SECRET = os.getenv('SALT_SECRET', 'default-salt-change-me')


def anonymize_ip(ip_address: str, salt: str = SALT_SECRET) -> str:
    """
    Anonymize an IP address using HMAC-SHA256.

    Args:
        ip_address: The IP address to anonymize
        salt: Secret salt for HMAC

    Returns:
        Hex-encoded HMAC hash
    """
    if not ip_address or ip_address == '0.0.0.0':
        return ''

    hmac_hash = hmac.new(
        salt.encode('utf-8'),
        ip_address.encode('utf-8'),
        hashlib.sha256
    )
    return hmac_hash.hexdigest()


def connect_to_clickhouse():
    """Connect to ClickHouse database."""
    try:
        client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD,
            database=CLICKHOUSE_DATABASE
        )
        print(f"[+] Connected to ClickHouse at {CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}")
        return client
    except Exception as e:
        print(f"[-] Failed to connect to ClickHouse: {e}")
        sys.exit(1)


def check_unanonymized_records(client, table_name: str, ip_field: str = 'source_ip') -> int:
    """
    Check if there are any records with unanonymized IPs.

    Args:
        client: ClickHouse client
        table_name: Name of the table to check
        ip_field: Name of the IP field to check

    Returns:
        Count of unanonymized records
    """
    try:
        query = f"""
        SELECT count()
        FROM {CLICKHOUSE_DATABASE}.{table_name}
        WHERE {ip_field} != ''
          AND {ip_field} != '0.0.0.0'
          AND source_ip_anon = ''
        """
        result = client.query(query)
        count = result.result_rows[0][0] if result.result_rows else 0

        if count > 0:
            print(f"[!] Found {count} unanonymized records in {table_name}")
        else:
            print(f"[+] No unanonymized records in {table_name}")

        return count
    except Exception as e:
        print(f"[-] Error checking {table_name}: {e}")
        return 0


def anonymize_table(client, table_name: str, ip_field: str = 'source_ip', dry_run: bool = False):
    """
    Anonymize IP addresses in a table.

    Args:
        client: ClickHouse client
        table_name: Name of the table to process
        ip_field: Name of the IP field to anonymize
        dry_run: If True, only show what would be done
    """
    print(f"\n[*] Processing table: {table_name}")

    # Check for unanonymized records
    count = check_unanonymized_records(client, table_name, ip_field)

    if count == 0:
        return

    if dry_run:
        print(f"[DRY RUN] Would anonymize {count} records in {table_name}")
        return

    # Fetch unanonymized IPs
    try:
        query = f"""
        SELECT DISTINCT {ip_field}
        FROM {CLICKHOUSE_DATABASE}.{table_name}
        WHERE {ip_field} != ''
          AND {ip_field} != '0.0.0.0'
          AND source_ip_anon = ''
        LIMIT 10000
        """
        result = client.query(query)
        ips = [row[0] for row in result.result_rows]

        print(f"[*] Found {len(ips)} unique IPs to anonymize")

        # Anonymize each IP
        updated = 0
        for ip in ips:
            anon_ip = anonymize_ip(ip)

            update_query = f"""
            ALTER TABLE {CLICKHOUSE_DATABASE}.{table_name}
            UPDATE source_ip_anon = '{anon_ip}'
            WHERE {ip_field} = '{ip}' AND source_ip_anon = ''
            """

            try:
                client.command(update_query)
                updated += 1

                if updated % 100 == 0:
                    print(f"[*] Anonymized {updated}/{len(ips)} IPs...")
            except Exception as e:
                print(f"[-] Failed to anonymize {ip}: {e}")

        print(f"[+] Successfully anonymized {updated} IP addresses in {table_name}")

        # Optionally remove the original IP field for privacy
        # (Uncomment if you want to delete original IPs after anonymization)
        # print(f"[*] Clearing original IP field in {table_name}...")
        # client.command(f"""
        #     ALTER TABLE {CLICKHOUSE_DATABASE}.{table_name}
        #     UPDATE {ip_field} = ''
        #     WHERE source_ip_anon != ''
        # """)

    except Exception as e:
        print(f"[-] Error during anonymization of {table_name}: {e}")


def anonymize_all_tables(client, dry_run: bool = False):
    """
    Anonymize IPs in all relevant tables.

    Args:
        client: ClickHouse client
        dry_run: If True, only show what would be done
    """
    tables_to_process = [
        ('events', 'source_ip'),
        ('ssh_events', 'source_ip'),
        ('http_events', 'source_ip'),
        ('ids_alerts', 'source_ip'),
        ('downloaded_files', 'source_ip'),
    ]

    print(f"\n{'='*60}")
    print(f"Starting IP Anonymization Process")
    print(f"Mode: {'DRY RUN' if dry_run else 'LIVE'}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    total_processed = 0

    for table_name, ip_field in tables_to_process:
        try:
            # Check if table exists
            check_query = f"""
            SELECT count()
            FROM system.tables
            WHERE database = '{CLICKHOUSE_DATABASE}'
              AND name = '{table_name}'
            """
            result = client.query(check_query)

            if result.result_rows[0][0] == 0:
                print(f"[!] Table {table_name} does not exist, skipping...")
                continue

            anonymize_table(client, table_name, ip_field, dry_run)
            total_processed += 1

        except Exception as e:
            print(f"[-] Error processing {table_name}: {e}")

    print(f"\n{'='*60}")
    print(f"Anonymization {'simulation' if dry_run else 'process'} completed")
    print(f"Tables processed: {total_processed}")
    print(f"{'='*60}\n")


def verify_anonymization(client):
    """Verify that all IPs have been anonymized."""
    print("\n[*] Verifying anonymization...")

    tables = ['events', 'ssh_events', 'http_events', 'ids_alerts', 'downloaded_files']
    all_good = True

    for table in tables:
        try:
            query = f"""
            SELECT count()
            FROM system.tables
            WHERE database = '{CLICKHOUSE_DATABASE}'
              AND name = '{table}'
            """
            result = client.query(query)

            if result.result_rows[0][0] == 0:
                continue

            count = check_unanonymized_records(client, table, 'source_ip')
            if count > 0:
                all_good = False
        except Exception as e:
            print(f"[-] Error verifying {table}: {e}")

    if all_good:
        print("\n[+] Verification complete: All IPs are anonymized!")
    else:
        print("\n[!] Verification complete: Some IPs still need anonymization")

    return all_good


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Anonymize IP addresses in IoT Honeypot database'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Only verify anonymization status'
    )
    parser.add_argument(
        '--table',
        type=str,
        help='Process only a specific table'
    )

    args = parser.parse_args()

    # Connect to database
    client = connect_to_clickhouse()

    if args.verify:
        # Only verify
        verify_anonymization(client)
    elif args.table:
        # Process specific table
        print(f"[*] Processing single table: {args.table}")
        anonymize_table(client, args.table, 'source_ip', args.dry_run)
        if not args.dry_run:
            verify_anonymization(client)
    else:
        # Process all tables
        anonymize_all_tables(client, args.dry_run)
        if not args.dry_run:
            verify_anonymization(client)

    print("[+] Done!")


if __name__ == '__main__':
    main()
