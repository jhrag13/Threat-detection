#!/usr/bin/env python3
"""
Enhanced CISA Threat Intelligence with Twitter and CVE Database
This script checks multiple threat intelligence sources including CISA feeds,
Twitter threat intelligence (optional), and CVE database information
"""

import requests
import json
from datetime import datetime, timedelta
import time
import xml.etree.ElementTree as ET
import re
import os

# Embedded SSH public key
SSH_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOFuX57n46/4vLilB8SKm7raYlDeWJqbhd39xs2/T7Cq your.email@example.com"

# Try to import BeautifulSoup, but make it optional
try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False
    print("Note: BeautifulSoup not available, using basic XML parsing")

# CISA Threat Intelligence Feeds
CISA_FEEDS = {
    "known_exploited_vulnerabilities": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "json"
    },
    "known_false_positive_ips": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known-false-positive-ips.txt",
        "type": "text"
    },
    "alerts_feed": {
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "type": "xml"
    },
    "bulletins_feed": {
        "url": "https://www.cisa.gov/uscert/ncas/bulletins.xml",
        "type": "xml"
    },
    "analysis_reports_feed": {
        "url": "https://www.cisa.gov/uscert/ncas/analysis-reports.xml",
        "type": "xml"
    },
    "emerging_threats": {
        "url": "https://www.cisa.gov/uscert/ncas/current-activity.xml",
        "type": "xml"
    }
}

# Additional threat intelligence feeds that don't require special libraries
ADDITIONAL_FEEDS = {
    "threatfox_ips": {
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "type": "json"
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "text"
    },
    "ci_army": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "text"
    }
}

# CVE Database API
CVE_API_URL = "https://cve.circl.lu/api/last"

# Try to import tweepy for Twitter integration, but make it optional
try:
    import tweepy
    TWITTER_AVAILABLE = True
except ImportError:
    TWITTER_AVAILABLE = False
    print("Note: Twitter integration disabled (tweepy library not installed)")

# Twitter API Configuration (set these as environment variables)
TWITTER_CONFIG = {
    "bearer_token": os.getenv("TWITTER_BEARER_TOKEN", ""),
    "consumer_key": os.getenv("TWITTER_API_KEY", ""),
    "consumer_secret": os.getenv("TWITTER_API_SECRET", ""),
    "access_token": os.getenv("TWITTER_ACCESS_TOKEN", ""),
    "access_token_secret": os.getenv("TWITTER_ACCESS_SECRET", "")
}

# Threat intelligence related Twitter accounts to monitor
THREAT_INTEL_TWITTER_ACCOUNTS = [
    "CISAgov",
    "USCERT_gov",
    "TheDFIRReport",
    "RedDrip7",
    "vxunderground",
    "MalwarePatrol",
    "MalwareTraffic",
    "abuse_ch",
    "CVEnew",
    "threatintel"
]

def display_ssh_key():
    """Display the embedded SSH public key"""
    print("=" * 80)
    print("EMBEDDED SSH PUBLIC KEY")
    print("=" * 80)
    print(SSH_PUBLIC_KEY)
    print()

def fetch_feed(feed_name, feed_config):
    """Fetch and parse a threat intelligence feed"""
    try:
        print(f"Fetching {feed_name.replace('_', ' ').title()}...")
        headers = {
            'User-Agent': 'CISA-Threat-Intel-Script/1.0'
        }
        response = requests.get(feed_config['url'], headers=headers, timeout=20)
        response.raise_for_status()
        
        if feed_config['type'] == 'json':
            return response.json()
        elif feed_config['type'] == 'xml':
            return parse_xml_feed(response.content)
        elif feed_config['type'] == 'text':
            return response.text.splitlines()
        else:
            return response.text
            
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {feed_name}: {e}")
        return None
    except (json.JSONDecodeError, ET.ParseError) as e:
        print(f"Error parsing {feed_name}: {e}")
        return None

def parse_xml_feed(xml_content):
    """Parse XML feeds from CISA"""
    try:
        root = ET.fromstring(xml_content)
        items = []
        
        # Parse RSS/Atom feed items
        for item in root.findall('.//item') or root.findall('.//entry'):
            item_data = {
                'title': get_xml_text(item, 'title'),
                'link': get_xml_text(item, 'link'),
                'published': get_xml_text(item, 'pubDate') or get_xml_text(item, 'published'),
                'description': get_xml_text(item, 'description') or get_xml_text(item, 'summary'),
                'guid': get_xml_text(item, 'guid') or get_xml_text(item, 'id')
            }
            items.append(item_data)
        
        return items
        
    except ET.ParseError:
        # Fallback to BeautifulSoup if available
        if BEAUTIFULSOUP_AVAILABLE:
            try:
                soup = BeautifulSoup(xml_content, 'xml')
                items = []
                for item in soup.find_all('item'):
                    items.append({
                        'title': item.title.text if item.title else 'No title',
                        'link': item.link.text if item.link else 'No link',
                        'published': item.pubDate.text if item.pubDate else 'No date',
                        'description': item.description.text if item.description else 'No description'
                    })
                return items
            except Exception as e:
                print(f"Error parsing XML with BeautifulSoup: {e}")
                return None
        else:
            print("XML parsing failed and BeautifulSoup not available")
            return None

def get_xml_text(element, tag_name):
    """Safely get text from XML element"""
    elem = element.find(tag_name)
    return elem.text if elem is not None else None

def fetch_twitter_threat_intel():
    """Fetch threat intelligence from Twitter using API"""
    if not TWITTER_AVAILABLE:
        print("Twitter integration not available (tweepy library not installed)")
        return None
    
    print("Fetching Twitter Threat Intelligence...")
    
    # Check if Twitter API is configured
    if not all(TWITTER_CONFIG.values()):
        print("Twitter API not configured. Set environment variables:")
        print("TWITTER_BEARER_TOKEN, TWITTER_API_KEY, TWITTER_API_SECRET")
        print("TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET")
        return None
    
    try:
        # Initialize Twitter client
        client = tweepy.Client(
            bearer_token=TWITTER_CONFIG["bearer_token"],
            consumer_key=TWITTER_CONFIG["consumer_key"],
            consumer_secret=TWITTER_CONFIG["consumer_secret"],
            access_token=TWITTER_CONFIG["access_token"],
            access_token_secret=TWITTER_CONFIG["access_token_secret"]
        )
        
        threat_tweets = []
        
        # Search for threat intelligence related tweets
        query = "(" + " OR ".join([f"from:{account}" for account in THREAT_INTEL_TWITTER_ACCOUNTS]) + ") AND (threat OR malware OR CVE OR vulnerability OR exploit)"
        
        # Get tweets from the last 24 hours
        start_time = (datetime.now() - timedelta(hours=24)).isoformat() + "Z"
        
        tweets = client.search_recent_tweets(
            query=query,
            max_results=20,
            start_time=start_time,
            tweet_fields=["created_at", "author_id", "public_metrics"],
            expansions=["author_id"],
            user_fields=["username", "name"]
        )
        
        # Process tweets
        if tweets.data:
            users = {u.id: u for u in tweets.includes['users']}
            
            for tweet in tweets.data:
                user = users.get(tweet.author_id)
                if user:
                    threat_tweets.append({
                        'text': tweet.text,
                        'author': user.username,
                        'name': user.name,
                        'created_at': tweet.created_at,
                        'retweet_count': tweet.public_metrics['retweet_count'],
                        'like_count': tweet.public_metrics['like_count']
                    })
        
        return threat_tweets
        
    except Exception as e:
        print(f"Error fetching Twitter data: {e}")
        return None

def fetch_recent_cves():
    """Fetch recent CVEs from CVE database"""
    print("Fetching Recent CVEs...")
    
    try:
        response = requests.get(CVE_API_URL, timeout=20)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVEs: {e}")
        return None

def fetch_additional_threat_feeds():
    """Fetch additional threat intelligence feeds"""
    results = {}
    
    for feed_name, feed_config in ADDITIONAL_FEEDS.items():
        data = fetch_feed(feed_name, feed_config)
        results[feed_name] = data
        
    return results

def display_known_exploited_vulnerabilities(data):
    """Display CISA Known Exploited Vulnerabilities"""
    print("=" * 80)
    print("CISA KNOWN EXPLOITED VULNERABILITIES CATALOG")
    print("=" * 80)
    
    if not data or 'vulnerabilities' not in data:
        print("No vulnerability data available")
        return
    
    vulnerabilities = data['vulnerabilities']
    print(f"Total Vulnerabilities: {len(vulnerabilities)}")
    print(f"Catalog Version: {data.get('catalogVersion', 'N/A')}")
    print(f"Date Released: {data.get('dateReleased', 'N/A')}")
    print()
    
    # Display the 8 most recent vulnerabilities
    recent_vulns = sorted(vulnerabilities, 
                         key=lambda x: x.get('dateAdded', ''), 
                         reverse=True)[:8]
    
    for i, vuln in enumerate(recent_vulns, 1):
        print(f"{i}. CVE ID: {vuln.get('cveID', 'N/A')}")
        print(f"   Vendor/Project: {vuln.get('vendorProject', 'N/A')}")
        print(f"   Product: {vuln.get('product', 'N/A')}")
        print(f"   Vulnerability Name: {vuln.get('vulnerabilityName', 'N/A')}")
        print(f"   Date Added: {vuln.get('dateAdded', 'N/A')}")
        print(f"   Due Date: {vuln.get('dueDate', 'N/A')}")
        print(f"   Required Action: {vuln.get('requiredAction', 'N/A')}")
        print(f"   Description: {vuln.get('shortDescription', 'N/A')[:120]}...")
        print("-" * 60)

def display_false_positive_ips(data):
    """Display CISA Known False Positive IPs"""
    print("=" * 80)
    print("CISA KNOWN FALSE POSITIVE IPs")
    print("=" * 80)
    
    if not data:
        print("No false positive IP data available")
        return
    
    print(f"Total False Positive IPs: {len(data)}")
    print()
    
    # Display IPs with timestamps if available
    ip_count = 0
    for line in data:
        if line.strip() and not line.strip().startswith('#'):
            ip_count += 1
            if ip_count <= 10:  # Show first 10 IP entries
                print(f"{ip_count}. {line.strip()}")
    
    if len(data) > 10:
        print(f"\n... and {len(data) - 10} more entries")

def display_feed_items(feed_name, items, max_items=5):
    """Display items from XML feeds (Alerts, Bulletins, Reports, Emerging Threats)"""
    print("=" * 80)
    print(f"CISA {feed_name.upper().replace('_', ' ')}")
    print("=" * 80)
    
    if not items:
        print(f"No {feed_name} data available")
        return
    
    print(f"Total Items: {len(items)}")
    print()
    
    for i, item in enumerate(items[:max_items], 1):
        print(f"{i}. Title: {item.get('title', 'No title')}")
        print(f"   Published: {item.get('published', 'No date')}")
        print(f"   Link: {item.get('link', 'No link')}")
        description = item.get('description', 'No description')
        # Clean up description text
        description = re.sub('<[^<]+?>', '', description)  # Remove HTML tags
        description = description.replace('\n', ' ').strip()
        print(f"   Description: {description[:150]}...")
        print("-" * 60)

def display_twitter_threats(tweets):
    """Display threat intelligence from Twitter"""
    print("=" * 80)
    print("TWITTER THREAT INTELLIGENCE")
    print("=" * 80)
    
    if not tweets:
        print("No Twitter threat data available")
        return
    
    print(f"Total Threat-Related Tweets: {len(tweets)}")
    print()
    
    for i, tweet in enumerate(tweets[:10], 1):
        print(f"{i}. Author: @{tweet.get('author', 'N/A')} ({tweet.get('name', 'N/A')})")
        print(f"   Time: {tweet.get('created_at', 'N/A')}")
        print(f"   Retweets: {tweet.get('retweet_count', 0)}, Likes: {tweet.get('like_count', 0)}")
        text = tweet.get('text', 'No text')
        # Clean up tweet text
        text = re.sub(r'http\S+', '', text)  # Remove URLs
        text = text.replace('\n', ' ')
        print(f"   Tweet: {text[:140]}...")
        print("-" * 60)

def display_recent_cves(cves):
    """Display recent CVEs"""
    print("=" * 80)
    print("RECENT CVEs (LAST 24 HOURS)")
    print("=" * 80)
    
    if not cves:
        print("No recent CVE data available")
        return
    
    print(f"Total Recent CVEs: {len(cves)}")
    print()
    
    for i, cve in enumerate(cves[:10], 1):
        print(f"{i}. CVE ID: {cve.get('id', 'N/A')}")
        print(f"   Published: {cve.get('Published', 'N/A')}")
        print(f"   Summary: {cve.get('summary', 'No description')[:120]}...")
        print(f"   CVSS Score: {cve.get('cvss', 'N/A')}")
        print(f"   References: {len(cve.get('references', []))}")
        print("-" * 60)

def display_additional_feeds(feeds_data):
    """Display additional threat intelligence feeds"""
    for feed_name, data in feeds_data.items():
        if not data:
            continue
            
        print("=" * 80)
        print(f"{feed_name.upper().replace('_', ' ')} THREAT INTELLIGENCE")
        print("=" * 80)
        
        if feed_name == "threatfox_ips" and isinstance(data, dict):
            # Display ThreatFox IOCs
            if 'data' in data:
                print(f"Total IOCs: {len(data['data'])}")
                print()
                for i, ioc in enumerate(data['data'][:10], 1):
                    print(f"{i}. IOC: {ioc.get('ioc', 'N/A')}")
                    print(f"   Type: {ioc.get('ioc_type', 'N/A')}")
                    print(f"   Malware: {ioc.get('malware', 'N/A')}")
                    print(f"   First Seen: {ioc.get('first_seen', 'N/A')}")
                    print("-" * 40)
        
        elif feed_name in ["blocklist_de", "ci_army"] and isinstance(data, list):
            # Display IP blocklists
            feed_title = "Blocklist.de" if feed_name == "blocklist_de" else "CI Army"
            print(f"Total Blocked IPs ({feed_title}): {len(data)}")
            print()
            for i, ip in enumerate(data[:15], 1):
                if ip.strip() and not ip.strip().startswith('#'):
                    print(f"{i}. {ip.strip()}")
            
            if len(data) > 15:
                print(f"\n... and {len([ip for ip in data if ip.strip() and not ip.strip().startswith('#')]) - 15} more entries")

def generate_threat_intelligence_report():
    """Generate a comprehensive threat intelligence report"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "feeds_checked": list(CISA_FEEDS.keys()) + ["twitter_threats", "recent_cves"] + list(ADDITIONAL_FEEDS.keys()),
        "results": {},
        "summary": {
            "total_vulnerabilities": 0,
            "total_alerts": 0,
            "total_bulletins": 0,
            "total_analysis_reports": 0,
            "total_emerging_threats": 0,
            "total_twitter_threats": 0,
            "total_recent_cves": 0
        }
    }
    
    # Fetch all feeds with rate limiting
    for feed_name, feed_config in CISA_FEEDS.items():
        data = fetch_feed(feed_name, feed_config)
        
        if data:
            if feed_name == "known_exploited_vulnerabilities":
                report['summary']['total_vulnerabilities'] = len(data.get('vulnerabilities', []))
            elif feed_name == "alerts_feed":
                report['summary']['total_alerts'] = len(data)
            elif feed_name == "bulletins_feed":
                report['summary']['total_bulletins'] = len(data)
            elif feed_name == "analysis_reports_feed":
                report['summary']['total_analysis_reports'] = len(data)
            elif feed_name == "emerging_threats":
                report['summary']['total_emerging_threats'] = len(data)
        
        report['results'][feed_name] = {
            'data_available': data is not None,
            'item_count': len(data) if data else 0,
            'last_checked': datetime.now().isoformat()
        }
        
        time.sleep(1)  # Be respectful to CISA servers
    
    # Fetch Twitter threats
    twitter_data = fetch_twitter_threat_intel()
    report['summary']['total_twitter_threats'] = len(twitter_data) if twitter_data else 0
    report['results']['twitter_threats'] = {
        'data_available': twitter_data is not None,
        'item_count': len(twitter_data) if twitter_data else 0,
        'last_checked': datetime.now().isoformat()
    }
    
    # Fetch recent CVEs
    cve_data = fetch_recent_cves()
    report['summary']['total_recent_cves'] = len(cve_data) if cve_data else 0
    report['results']['recent_cves'] = {
        'data_available': cve_data is not None,
        'item_count': len(cve_data) if cve_data else 0,
        'last_checked': datetime.now().isoformat()
    }
    
    # Fetch additional threat feeds
    additional_data = fetch_additional_threat_feeds()
    for feed_name, data in additional_data.items():
        report['results'][feed_name] = {
            'data_available': data is not None,
            'item_count': len(data) if data else 0,
            'last_checked': datetime.now().isoformat()
        }
    
    return report

def main():
    """Main function"""
    print("ENHANCED THREAT INTELLIGENCE SCRIPT")
    print("Generated on:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print()
    
    # Display the SSH key
    display_ssh_key()
    
    # Fetch and display all threat intelligence feeds
    feeds_data = {}
    
    for feed_name, feed_config in CISA_FEEDS.items():
        data = fetch_feed(feed_name, feed_config)
        feeds_data[feed_name] = data
        time.sleep(1)  # Rate limiting
    
    # Fetch Twitter threats
    twitter_data = fetch_twitter_threat_intel()
    
    # Fetch recent CVEs
    cve_data = fetch_recent_cves()
    
    # Fetch additional threat feeds
    additional_data = fetch_additional_threat_feeds()
    
    # Display all feeds
    if 'known_exploited_vulnerabilities' in feeds_data:
        display_known_exploited_vulnerabilities(feeds_data['known_exploited_vulnerabilities'])
    
    if 'known_false_positive_ips' in feeds_data:
        display_false_positive_ips(feeds_data['known_false_positive_ips'])
    
    if 'alerts_feed' in feeds_data:
        display_feed_items("Security Alerts", feeds_data['alerts_feed'])
    
    if 'bulletins_feed' in feeds_data:
        display_feed_items("Security Bulletins", feeds_data['bulletins_feed'])
    
    if 'analysis_reports_feed' in feeds_data:
        display_feed_items("Analysis Reports", feeds_data['analysis_reports_feed'])
    
    if 'emerging_threats' in feeds_data:
        display_feed_items("Emerging Threats & Current Activity", feeds_data['emerging_threats'])
    
    # Display Twitter threats
    if twitter_data:
        display_twitter_threats(twitter_data)
    
    # Display recent CVEs
    display_recent_cves(cve_data)
    
    # Display additional threat feeds
    display_additional_feeds(additional_data)
    
    # Generate summary report
    print("=" * 80)
    print("THREAT INTELLIGENCE SUMMARY REPORT")
    print("=" * 80)
    report = generate_threat_intelligence_report()
    
    print(f"Report Timestamp: {report['timestamp']}")
    print("\nFeed Statistics:")
    print(f"  • Known Exploited Vulnerabilities: {report['summary']['total_vulnerabilities']}")
    print(f"  • Security Alerts: {report['summary']['total_alerts']}")
    print(f"  • Security Bulletins: {report['summary']['total_bulletins']}")
    print(f"  • Analysis Reports: {report['summary']['total_analysis_reports']}")
    print(f"  • Emerging Threats: {report['summary']['total_emerging_threats']}")
    print(f"  • Twitter Threat Posts: {report['summary']['total_twitter_threats']}")
    print(f"  • Recent CVEs: {report['summary']['total_recent_cves']}")
    
    print("\n" + "=" * 80)
    print("SECURITY RECOMMENDATIONS")
    print("=" * 80)
    print("1. Regularly monitor CISA feeds for emerging threats")
    print("2. Prioritize patching known exploited vulnerabilities")
    print("3. Implement the recommended actions from CISA alerts")
    print("4. Use the false positive IP list to reduce alert noise")
    print("5. Subscribe to CISA notifications for real-time updates")
    print("6. Integrate these feeds into your SIEM/SOC workflow")
    print("7. Conduct regular threat hunting based on CISA intelligence")
    print("8. Monitor Twitter for real-time threat intelligence")
    print("9. Stay updated on recent CVEs affecting your infrastructure")
    print("10. Consider automating threat intelligence collection and analysis")

if __name__ == "__main__":
    main()