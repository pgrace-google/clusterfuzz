# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Automated ingestion of testcases via IssueTracker."""

import re

import requests

from appengine.libs import form
from appengine.libs import gcs
from appengine.libs import helpers
from clusterfuzz._internal.issue_management.google_issue_tracker import \
    issue_tracker


from googleapiclient.discovery import build
from oauth2client import tools
from oauth2client.file import Storage
from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import flow_from_clientsecrets
from oauth2client.service_account import ServiceAccountCredentials
from google.oauth2.service_account import Credentials
import httplib2
from google.oauth2 import service_account
from googleapiclient.discovery import build
from clusterfuzz._internal.google_cloud_utils import credentials
import google_auth_httplib2

import csv
ACCEPTED_FILETYPES = [
    'text/javascript', 'application/pdf', 'text/html', 'application/zip'
]


def close_invalid_issue(upload_request, attachment_info, description):
  """Closes any invalid upload requests with a helpful message."""
  comment_messsage = (
      'Hello, this issue is automatically closed. Please file a new bug after'
      'fixing the following issues:\n\n')
  invalid = False

  # TODO(pgrace) remove after testing.
  if upload_request.id == '373893311':
    return False

  # TODO(pgrace) add secondary check for authorized reporters.

  # Issue must have exactly one attachment.
  if len(attachment_info) != 1:
    comment_messsage += 'Please provide exactly one attachment.\n'
    invalid = True
  else:
    # Issue must use one of the supported testcase file types.
    if attachment_info[0]['contentType'] not in ACCEPTED_FILETYPES:
      comment_messsage += (
          'Please provide an attachment of type: html, js, pdf, or zip.\n')
      invalid = True
    if not attachment_info[0]['attachmentDataRef'] or \
      not attachment_info[0]['attachmentDataRef']['resourceName'] \
        or not attachment_info[0]['filename']:
      comment_messsage += \
        'Please check that the attachment uploaded successfully.\n'
      invalid = True

  # Issue must have valid flags as the description.
  flag_format = re.compile(r'^([ ]?\-\-[A-Za-z\-\_]*){50}$')
  if flag_format.match(description):
    comment_messsage += (
        'Please provide flags in the format: "--test_flag_one --testflagtwo",\n'
    )
    invalid = True

  if invalid:
    comment_messsage += (
        '\nPlease see the new bug template for more information on how to use'
        'Clusterfuzz direct uploads.')
    upload_request.status = 'not_reproducible'
    upload_request.save(new_comment=comment_messsage, notify=True)

  return invalid


def submit_testcase(issue_id, file, filename, filetype, cmds):
  """Uploads the given testcase file to Clusterfuzz."""
  if filetype == 'text/javascript':
    job = 'linux_asan_d8_dbg'
  elif filetype == 'application/pdf':
    job = 'libfuzzer_pdfium_asan'
  elif filetype == 'text/html':
    job = 'linux_asan_chrome_mp'
  elif filetype == 'application/zip':
    job = 'linux_asan_chrome_mp'
  else:
    raise TypeError
  upload_info = gcs.prepare_blob_upload()._asdict()

  data = {
      # Content provided by uploader.
      'issue': issue_id,
      'job': job,
      'file': file,
      'cmd': cmds,
      'x-goog-meta-filename': filename,

      # Content generated internally.
      'platform': 'Linux',
      'csrf_token': form.generate_csrf_token(),
      'upload_key': upload_info['key'],
      # TODO(pgrace) replace with upload_info['bucket'] once testing complete.
      'bucket': 'clusterfuzz-test-bucket',
      'key': upload_info['key'],
      'GoogleAccessId': upload_info['google_access_id'],
      'policy': upload_info['policy'],
      'signature': upload_info['signature'],
  }

  return requests.post(
      "https://clusterfuzz.com/upload-testcase/upload", data=data, timeout=10)


def check_reporter_membership(reporter_email):
#   # scope = 'https://www.googleapis.com/auth/admin.directory.group'
  scope = 'https://www.googleapis.com/auth/admin.directory.group.readonly'
  # credentials = ServiceAccountCredentials.from_json() ('246243303817.project.googleusercontent.com',
  #                                                         'src/clusterfuzz/_internal/cron/cs.p12',
  #                                                         scopes=scope)  
  # credentials = Credentials.from_service_account_file('/tmp/sa-key', scopes=[scope])
# credentials = credentials.create_delegated('admin@demoapp2.com')
#   # credentials = SignedJwtAssertionCredentials('246243303817@project.googleusercontent.com', '246243303817.project.googleusercontent.com', '7Li-_L5vDvTm3wQ8QyCxuRp7', scope)
  # http = httplib2.Http()
  # http = credentials.authorize(http)
  # service = build('admin', 'directory_v1', http=http)
#   service = build('admin', 'directory_v1', credentials=credentials)
#   # service = build('admin', 'directory_v1')
#   request = service.members().list(groupKey='clusterfuzz-vrp-uploaders@chromium.org')
#   response = request.execute()
#   if response and 'members' in response:
#       instances = response['members']
#       for instance in instances:
#           print(instance['email'])
#   else:
#       print
#       'There are no members to list in this group.'

  # upload_info = gcs.prepare_blob_upload()._asdict()
  # data = {
  #     'upload_key': upload_info['key'],
  #     'key': upload_info['key'],
  #     'GoogleAccessId': upload_info['google_access_id'],
  #     'policy': upload_info['policy'],
  #     'signature': upload_info['signature'],
  # }
  # v = requests.get('https://admin.googleapis.com/admin/directory/v1/groups/clusterfuzz-vrp-uploaders@chromium.org/hasMember/' + 'pgrace@google.com', data=data, timeout=10)
  # print(v)

  # credentials = service_account.Credentials.from_service_account_file (
  #   '/tmp/sa-key',
  #   scopes=['https://www.googleapis.com/auth/admin.directory.group.readonly',
  #           'https://www.googleapis.com/auth/admin.directory.group.member.readonly']
  # )# Delegated credentials for admin actions
  # delegated_credentials = credentials.with_subject('pgrace@google.com')

  # # Create the service client
  # service = build('admin', 'directory_v1', credentials=delegated_credentials)
  # request = service.members().list(groupKey='clusterfuzz-vrp-uploaders@chromium.org')
  # response = request.execute()
  # print(response)

  creds = credentials.get_default(scopes=['https://www.googleapis.com/auth/admin.directory.group.member.readonly'])[0]
  http = google_auth_httplib2.AuthorizedHttp(
      creds, http=httplib2.Http(timeout=10))

  service = build('admin', 'directory_v1', http=http, cache_discovery=False)
  request = service.members().list(groupKey='clusterfuzz-vrp-uploaders@chromium.org')
  response = request.execute()
  print(response)

def handle_testcases(tracker):
  """Fetches and submits testcases from bugs or closes unnecssary bugs."""
  # TODO(pgrace) replace once testing complete with
  # tracker.get_issues(["componentid:1600865"], is_open=True).
  issues = [tracker.get_issue(373893311)]

  # TODO(pgrace) implement rudimentary rate limiting

  for issue in issues:
    # TODO(pgrace) close out older bugs that may have failed to reproduce

    attachment_metadata = tracker.get_attachment_metadata(issue.id)
    commandline_flags = tracker.get_description(issue.id)
    if close_invalid_issue(issue, attachment_metadata, commandline_flags):
      helpers.log("Closing issue {issue_id} as it is invalid", issue.id)
      continue
    # TODO(pgrace) replace with 0 once testing is complete
    attachment_metadata = attachment_metadata[6]
    attachment = tracker.get_attachment(
        attachment_metadata['attachmentDataRef']['resourceName'])
    submit_testcase(issue.id, attachment, attachment_metadata['filename'],
                    attachment_metadata['contentType'], commandline_flags)
    helpers.log("Submitted testcase file for issue {issue_id}", issue.id)


def main():
  # tracker = issue_tracker.IssueTracker('chromium', None,
                                      #  {'default_component_id': 1363614})
  # handle_testcases(tracker)
  check_reporter_membership("pgrace@google.com")


if __name__ == '__main__':
  main()
