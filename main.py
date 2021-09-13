import re
import sys
import time
import smtplib
from difflib import ndiff
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec


def make_driver():
    chrome_options = Options()
    chrome_options.add_argument('headless')
    chrome_options.add_argument("--disable-gpu")
    driver = webdriver.Chrome(options=chrome_options)
    return driver


def read_preferences():
    print('Loading preferences...')
    preferences = {'credentials': [], 'links': []}
    with open(sys.path[0]+'/preferences.txt') as f:
        lines = [line.rstrip('\n') for line in f]
        for line in lines:
            if line.startswith('CREDENTIAL-'):
                cred = {}
                line = line.replace('CREDENTIAL-', '')
                pieces = line.split(',')
                for piece in pieces:
                    if piece.startswith('site:'):
                        cred['site'] = piece.replace('site:', '')
                    elif piece.startswith('link:'):
                        cred['link'] = piece.replace('link:', '')
                    elif piece.startswith('username'):
                        cred['username'] = piece.replace('username:', '')
                    elif piece.startswith('password'):
                        cred['password'] = piece.replace('password:', '')
                    else:
                        raise Exception('Failed parsing preferences. Credential malformed: ' + line)
                if not all(key in cred for key in ['site', 'link', 'username', 'password']):
                    raise Exception('Failed parsing preferences. Credential malformed: ' + line)
                preferences['credentials'].append(cred)
            elif line.startswith('LINK-'):
                line = line.replace('LINK-', '')
                pieces = line.split(',')
                link = {}
                for piece in pieces:
                    if piece.startswith('link:'):
                        link['link'] = piece.replace('link:', '')
                    elif piece.startswith('site:'):
                        link['site'] = piece.replace('site:', '')
                    elif piece.startswith('needs_credentials'):
                        link['needs_credentials'] = True
                    else:
                        raise Exception('Failed parsing preferences. Site malformed: ' + line)
                if 'link' not in link or 'site' not in link:
                    raise Exception('Failed parsing preferences. Site malformed: ' + line)
                preferences['links'].append(link)
    if len(preferences['links']) == 0:
        raise Exception('No links in preferences.')
    print('Got links:')
    for link in preferences['links']:
        print('     ' + link['link'])
    if len(preferences['credentials']) > 0:
        print('Got credentials for:')
        for cred in preferences['credentials']:
            print('     ' + cred['site'])
    missing_creds = list(
        filter(
            lambda l: 'needs_credentials' in l and not any(c['site'] == l['site'] for c in preferences['credentials']),
            preferences['links']))
    if len(missing_creds) > 0:
        error_text = '\nMissing credentials for:'
        for link in missing_creds:
            error_text = error_text + ('\n      ' + link['site'])
        raise Exception(error_text)
    missing_site_function = list(
        filter(lambda l: l not in site_functions, [li['site'] for li in preferences['links']]))
    if len(missing_site_function) > 0:
        error_text = '\nMissing site function for:'
        for link in missing_site_function:
            error_text = error_text + ('\n      ' + link['site'])
        raise Exception(error_text)
    missing_login_function = list(
        filter(lambda l: l not in login_functions, [c['site'] for c in preferences['credentials']]))
    if len(missing_login_function) > 0:
        error_text = '\nMissing login function for:'
        for link in missing_login_function:
            error_text = error_text + ('\n      ' + link['site'])
        raise Exception(error_text)
    return preferences


def send_email(from_email, password, to_email, subject, message):
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.ehlo()
        server.login(from_email.strip(), password.strip())
        msg = "Subject: " + subject + "\n\n" + str(message)
        server.sendmail(from_email, to_email, msg)
        print('Email sent.')


def get_email_info():
    print('Checking for email info...')
    if not (len(sys.argv) == 4 and re.fullmatch(email_regex, sys.argv[1]) and re.fullmatch(email_regex, sys.argv[3])):
        if len(sys.argv) > 1:
            print('Invalid email arguments ' + str(sys.argv[1:]))
        print('No email info.')
        return None, None, None
    print('Found email info.')
    return sys.argv[1], sys.argv[2], sys.argv[3]


def login_to_gradescope(driver, link, username, password):
    driver.get(link)
    try:
        driver.find_element_by_class_name('sidebar--userProfile')
        return driver
    except:
        driver.find_element_by_class_name('js-logInButton').click()
        WebDriverWait(driver, 15).until(ec.presence_of_element_located((By.ID, "session_email")))
        driver.find_element_by_id('session_email').send_keys(username)
        driver.find_element_by_id('session_password').send_keys(password)
        driver.find_element_by_xpath("//input[@value='Log In']").click()
        WebDriverWait(driver, 15).until(ec.presence_of_element_located((By.CLASS_NAME, "sidebar--userProfile")))
        return driver


def check_gradescope_link(driver, link):
    driver.get(link)
    assignments = driver.find_element_by_id('assignments-student-table')
    assignment_rows = assignments.find_elements_by_css_selector('tbody')[0].find_elements_by_css_selector('tr')
    assignments = '|'
    for assignment in assignment_rows:
        assignment_text = ' '+assignment.find_elements_by_css_selector('th')[0].text.strip()
        assignment_text += ', '+assignment.find_element_by_class_name('submissionStatus').text.strip()
        assignment_text += ', '+assignment.find_element_by_class_name('progressBar--caption').text.strip()+' |'
        assignments += assignment_text.replace('\n', '')
    return assignments


def recurse_on_iframes(driver):
    text = driver.find_element_by_xpath("/html/body").text
    for iframe in driver.find_elements_by_tag_name('iframe'):
        driver.switch_to.frame(iframe)
        text += recurse_on_iframes(driver)
    return text


def check_plain_text_link(driver, link):
    driver.get(link)
    time.sleep(5)
    text = recurse_on_iframes(driver)
    return text.replace('\n', '').split('Last updated')[0]


def compare_results(results):
    changes = []
    with open(sys.path[0] + '/link_states.txt', 'r+') as f:
        lines = [line.rstrip('\n') for line in f.readlines()]
        newlines = lines.copy()
        for key in results:
            line = list(filter(lambda l: l.startswith(key), lines))
            if len(line) == 0:
                newlines.append(key + '=' + results[key])
            elif len(line) == 1:
                value = line[0].replace(key + '=', '').strip()
                previous_words = [val.strip() for val in value.split()]
                new_words = [val.strip() for val in results[key].split()]
                change_list = [d for d in ndiff(previous_words, new_words) if d.startswith('-') or d.startswith('+')]
                if len(change_list) > 0:
                    changes.append([key, ' '.join(change_list)])
                    newlines = list(map(lambda x: key + '=' + results[key] if x == line[0] else x, newlines))
    with open(sys.path[0] + '/link_states.txt', 'w') as f:
        for line in newlines:
            f.write(line + '\n')
    return changes


email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
login_functions = {
    'Gradescope': login_to_gradescope
}
site_functions = {
    'Gradescope': check_gradescope_link,
    'Plain text': check_plain_text_link
}


def main():
    from_email, password, to_email = get_email_info()
    try:
        prefs = read_preferences()
    except Exception as e:
        print(e)
        if from_email:
            print('Emailing ' + to_email + '...')
            try:
                send_email(from_email, password, to_email, 'ERROR: Assignment Checker Failed', e)
            except Exception as er:
                print('Failed emailing ' + to_email + ': ' + str(er))
        return None
    with make_driver() as driver:
        results = {}
        failures = []
        for link in prefs['links']:
            print('Checking ' + link['link'] + '...')
            if 'needs_credentials' in link:
                print('Logging in to ' + link['site'] + '...')
                try:
                    creds = list(filter(lambda c: c['site'] == link['site'], prefs['credentials']))[0]
                    driver = login_functions[link['site']](driver, creds['link'], creds['username'], creds['password'])
                    print('Logged in.')
                except Exception as e:
                    print('Failed logging in to ' + link['site'])
                    print(e)
                    if from_email:
                        failures.append('Failed logging in.\n'+link['site']+'\n'+str(e))
                    break
            try:
                results[link['link']] = site_functions[link['site']](driver, link['link'])
            except Exception as e:
                print('Failed checking ' + link['link'])
                print(e)
                if from_email:
                    failures.append('Failed checking. \n'+link['site']+'\n'+str(e))
        try:
            changes = compare_results(results)
            if len(changes) > 0 or len(failures) > 0:
                change_string = 'Checking completed. Results:\n'
                for change in changes:
                    change_string = change_string + '     ' + change[0] + ': ' + change[1] + '\n'
                for failure in failures:
                    change_string += '\n'+failure
                subject = 'ALERT: Assignment Checker Found Changes'
                if len(failures) > 0:
                    subject = 'ERROR: Assignment Checker Failed'
                if from_email:
                    print('Emailing ' + to_email + '...')
                    try:
                        send_email(from_email, password, to_email, subject, change_string)
                    except Exception as er:
                        print('Failed emailing ' + to_email + ': ' + str(er))
                print(change_string)
            else:
                print('Checking completed. No changes found.')
        except Exception as e:
            print('Failed parsing results')
            print(e)
            if from_email:
                print('Emailing ' + to_email + '...')
                try:
                    send_email(from_email, password, to_email, 'ERROR: Assignment Checker Failed', e)
                except Exception as er:
                    print('Failed emailing ' + to_email + ': ' + str(er))
    return


if __name__ == "__main__":
    main()
