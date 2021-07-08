#!/usr/bin/env python
"""
@Author: gardenqiu
@mail: gardenqiu@Tencent.com
"""
""" a simple deploy script for deploy a new application in a cluster """

from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.tsf.v20180326 import tsf_client, models
from qcloud_cos import CosConfig
from qcloud_cos import CosS3Client


import json,argparse
import hashlib, hmac, time,requests,sys,os
from datetime import datetime

# replace "#" with your credentials
secret_id = "#"
secret_key = "#"
clusterId = "#"
namespace = "#"

service = "tsf"
host = "tsf.tencentcloudapi.com"
endpoint = "https://" + host
region = "ap-shanghai"
version = "2018-03-26"
algorithm = "TC3-HMAC-SHA256"


def getMd5(file_path):
    """
    get the Md5 of the file
    :param file_path:
    :return: md5
    """
    f = open(file_path, 'rb')
    md5_obj = hashlib.md5()
    md5_obj.update(f.read())
    hash_code = md5_obj.hexdigest()
    f.close()
    md5 = str(hash_code).lower()
    return md5


def getClient():
    """
    get the tsf client
    :return:
    """
    try:
        cred = credential.Credential(secret_id, secret_key)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "tsf.tencentcloudapi.com"

        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = tsf_client.TsfClient(cred, region, clientProfile)
        return client
    except TencentCloudSDKException as err:
        print "********* Get TSF client Error *********"
        print err



def getHeader(params, action, http_request_method, host=host, version=version, region=region):
    """
    when the API is not public, make the header with this function, and make the requests.
    :param params: request params
    :param action: the action name of the request
    :param http_request_method: http methond ,"POST" or "GET"
    :param host: host name
    :param version: API version
    :param region: the region of the cluster
    :return: header
    """
    timestamp = int(time.time())
    date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")
    canonical_uri = "/"

    canonical_querystring = ""
    ct = "x-www-form-urlencoded"
    payload = ""
    if http_request_method == "POST":
        canonical_querystring = ""
        ct = "json"
        payload = json.dumps(params)
    canonical_headers = "content-type:application/%s\nhost:%s\n" % (ct, host)
    signed_headers = "content-type;host"
    hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical_request = (http_request_method + "\n" +
                         canonical_uri + "\n" +
                         canonical_querystring + "\n" +
                         canonical_headers + "\n" +
                         signed_headers + "\n" +
                         hashed_request_payload)
    # print(canonical_request)

    credential_scope = date + "/" + service + "/" + "tc3_request"
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = (algorithm + "\n" +
                      str(timestamp) + "\n" +
                      credential_scope + "\n" +
                      hashed_canonical_request)
    # print(string_to_sign)

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    secret_date = sign(("TC3" + secret_key).encode("utf-8"), date)
    secret_service = sign(secret_date, service)
    secret_signing = sign(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    # print(signature)

    authorization = (algorithm + " " +
                     "Credential=" + secret_id + "/" + credential_scope + ", " +
                     "SignedHeaders=" + signed_headers + ", " +
                     "Signature=" + signature)
    # print(authorization)

    headers = {
        "Authorization": authorization,
        "Host": host,
        "Content-Type": "application/%s" % ct,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": version,
        "X-TC-Region": region,
    }
    return headers


def get_file_type(path):
    type_dict = {
        ".tar.gz": "tar.gz",
        ".jar": "fatjar",
        ".war": "war",
        ".zip": "zip"
    }
    for suffix in type_dict.keys():
        if path.endswith(suffix):
            return type_dict[suffix]
    else:
        raise Exception("Unknown file type")


def createApplication(applicationName, applicationType, MicroserivceType):
    """
    create a new application
    :param applicationName: the name of the application
    :param applicationType: CVM or container
    :param MicroserivceType: the application type NATIVE or not
    :return: applicationId
    """
    try:
        #make requests
        req = models.CreateApplicationRequest()
        params = {
            "ApplicationName": applicationName,
            "ApplicationType": applicationType,
            "MicroserviceType": MicroserivceType
        }

        req.from_json_string(json.dumps(params))

        resp = client.CreateApplication(req)
        print ("Create application Success!" + resp.to_json_string())
        applicationId = json.loads(resp.to_json_string())['Result']

        return applicationId

    except TencentCloudSDKException as err:
        print err


def createGroup(applicationId, groupName):
    """
    create a new group
    :param applicationId: a new group must bind to a application.
    :param groupName: the name of the application
    :return: groupId
    """
    try:

        #make requests
        req = models.CreateGroupRequest()
        params = {
            "ApplicationId": applicationId,
            "NamespaceId": namespace,
            "GroupName": groupName,
            "ClusterId": clusterId
        }

        req.from_json_string(json.dumps(params))

        resp = client.CreateGroup(req)
        groupId = json.loads(resp.to_json_string())["Result"]
        print "Create Group Success! GroupId: {}".format(groupId)
        return groupId

    except TencentCloudSDKException as err:
        print "********* Create Group Error *********"
        print err


def describeGroupAddibleInstance(groupId):
    """
    After create the deploy group, check the available instance to the group.
    not public API
    :param groupId:
    :return: the list of available instances
    """
    params = dict(GroupId=groupId)
    headers = getHeader(params, "DescribeGroupAddibleInstances", "POST")
    resp = requests.post(endpoint, headers=headers,data=json.dumps(params))
    responses = json.loads(resp.content)["Response"]["Result"]
    if responses["TotalCount"] == 0:
        print "Error!!! There is not available Instance for the deploy, Please buy " \
              "the CVM first, and Make sure it is added to the Cluster: {}".format(clusterId)
        sys.exit()
    instances = []
    for content in responses["Content"]:
        instances.append(content["InstanceId"])
    print "available instance : {}".format(repr(instances))
    return instances


def describePkgs(applicationId, pkgversion = None):
    """
    Get the pkg in the application with pkgversion
    :param applicationId: the aim application ID
    :param pkgversion: the aim pkgversion
    :return: type: json, search result
    """
    try:
        req = models.DescribePkgsRequest()
        params = {
            "ApplicationId": applicationId,
            "SearchWord": pkgversion
        }

        req.from_json_string(json.dumps(params))

        resp = client.DescribePkgs(req)
        responses = json.loads(resp.to_json_string())["Result"]
        return responses
    except TencentCloudSDKException as err:
        print "********* Describe Pkgs Instance Error *********"
        print err


def describeUploadInfo(applicationId, pkgName, pkgVersion, pkgType):
    """
    Get the upload package info
    :param applicationId: the application ID
    :param pkgName: the package name of your uploading
    :param pkgVersion: the version of the package.
    :param pkgType: the type of the package, must in ["tar.gz","fatjar","war", "zip"]
    :return:
    """

    if pkgType not in ["tar.gz","fatjar","war", "zip"]:
        print "[ERROR] ERROR package type!!! you shoud be one of [\"tar.gz\",\"fatjar\",\"war\", \"zip\"]"
        sys.exit()
    try:
        req = models.DescribeUploadInfoRequest()
        params = {
            "ApplicationId": applicationId,
            "PkgName": pkgName,
            "PkgVersion": pkgVersion,
            "PkgType": pkgType
        }
        req.from_json_string(json.dumps(params))

        resp = client.DescribeUploadInfo(req)
        uploadInfo = json.loads(resp.to_json_string())["Result"]
        print "Get uploadInfo Success! {}".format(uploadInfo)
        return uploadInfo
    except TencentCloudSDKException as err:
        print "********* Describe UploadInfo Error *********"
        print err


def uploadFile(path, uploadInfo, applicationId, app_Id, pkg_version):
    """
    upload the file package to the cloud
    not public API
    :param path: local path of the package
    :param uploadInfo: uploadInfo get by the describeUploadInfo
    :param applicationId: application ID
    :param app_Id: app ID
    :param pkg_version:
    :return:
    """
    try:
        credential = uploadInfo['Credentials']
        secret_id = credential['TmpSecretId']
        secret_key = credential['TmpSecretKey']
        token = credential['SessionToken']
        scheme = 'https'
        config = CosConfig(Region=region, SecretId=secret_id, SecretKey=secret_key, Token=token, Scheme=scheme)
        client = CosS3Client(config)

        file_name = os.path.basename(path)
        key = app_Id + "/" + applicationId + "/" + pkg_version + "/" + file_name
        response = client.upload_file(
            Bucket=uploadInfo['Bucket'],
            LocalFilePath=path,
            Key=key,
            PartSize=1,
            MAXThread=10,
            EnableMD5=True
        )
        print "upload file Success!" + repr(response)
        modifyUploadInfo(path,applicationId, uploadInfo["PkgId"], result=0)
    except Exception as e:
        # when upload failin, delete the information of the information of the pak.
        pkgs = describePkgs(applicationId, pkg_version)
        if pkgs["TotalCount"] > 0:
            pkgsId = []
            for pkg in pkgs["Content"]:
                pkgsId.append(pkg["PkgId"])
            deletePkgs(applicationId, pkgsId)
        print "Upload file: {} failed! Please Try again!"
        print e


def deletePkgs(applicationId, pkgIds):
    """
    delete packages
    :param applicationId:
    :param pkgIds:
    :return:
    """
    try:
        req = models.DeletePkgsRequest()
        params = {
            "ApplicationId": applicationId,
            "PkgIds": pkgIds
        }
        req.from_json_string(json.dumps(params))

        resp = client.DeletePkgs(req)
        print(resp.to_json_string())
    except TencentCloudSDKException as err:
        print "Delete Pak error,Pkgs:{}".format(pkgIds)
        print pkgIds


def modifyUploadInfo(path, applicationId, pkgId, result):
    """
    modify upload Info after upload the package file
    :param path: local file path
    :param applicationId:
    :param pkgId:
    :param result:
    :return:
    """
    md5 = getMd5(path)
    try:
        req = models.ModifyUploadInfoRequest()
        params = {
            "ApplicationId": applicationId,
            "PkgId": pkgId,
            "Result": result,
            "Md5": md5
        }
        req.from_json_string(json.dumps(params))

        resp = client.ModifyUploadInfo(req)
        print "upload package success !" +  resp.to_json_string()
    except TencentCloudSDKException as err:
        print "********* Describe Pkgs Instance Error *********"
        print err


def expandGroup(groupId, instances):
    """
    add the instance to the deploy group
    :param groupId:
    :param instances:
    :return:
    """
    try:
        req = models.ExpandGroupRequest()
        params = {
            "GroupId": groupId,
            "InstanceIdList": instances
        }
        req.from_json_string(json.dumps(params))

        resp = client.ExpandGroup(req)

        print("Expand Group Success !" + resp.to_json_string())
    except TencentCloudSDKException as err:
        print "********* expandGroup Error *********"
        print err

def deployGroup(groupId, pkgId):
    """
    Deploy Group
    :param groupId:
    :param pkgId:
    :return:
    """
    try:
        req = models.DeployGroupRequest()
        params = {
            "GroupId": groupId,
            "PkgId": pkgId
        }
        req.from_json_string(json.dumps(params))

        resp = client.DeployGroup(req)
        print( "Deploy group Success!" + resp.to_json_string())
    except TencentCloudSDKException as err:
        print "********* Deploy Group Instance Error *********"
        print err


def Main(path, pkgVersion, appId,applicationName, applicationType, microserviceType, groupName):

    pkgType = get_file_type(path)
    pkgName = os.path.basename(path)
    applicationId = createApplication(applicationName, applicationType, microserviceType)
    if not applicationId:
        print "[Error] createApplication Error, Maybe the applicationName is duplicated, Please make sure you do not have" \
              " Exist application with the same Name"
        sys.exit()
    response = describePkgs(applicationId, pkgVersion)
    if response["TotalCount"] > 0:
        print "[INFO] {} has uploaded version {}, no need upload".format(applicationId, pkgVersion)
        pkgsId =[]
        for pkg in response["Content"]:
              pkgsId.append(pkg["PkgId"])
        pkgId = pkgsId[0]
    else:
        uploadInfo = describeUploadInfo(applicationId, pkgName=pkgName, pkgVersion=pkgVersion, pkgType=pkgType)
        uploadFile(path, uploadInfo, applicationId, appId, pkg_version=pkgVersion)
        pkgId = uploadInfo['PkgId']
    groupId = createGroup(applicationId, groupName=groupName)
    if not groupId:
        print "[Error] createGroup Error, Maybe the Group is duplicated, Please make sure you do not have" \
              " Exist Group with the same Name"
        sys.exit()
    instances = describeGroupAddibleInstance(groupId)
    if len(instances) < 1:
        print "[Error] There is no available Instance for your deployment, Please buy the CVM and add it the cluster you" \
              " want to deploy the application"
        sys.exit()
    expandGroup(groupId, instances)
    deployGroup(groupId=groupId, pkgId=pkgId)

def argsParser():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help= "The path to the application package, and it should be in [tar.gz,jar,war,zip]")
    parser.add_argument("applicationName", help="Input a applicationName, must be Unique")
    parser.add_argument("appId", help="you AppID of you account information")
    parser.add_argument("--groupName", help="Input a group name for you deploy group, must be Unique,default the same"
                                            " with application name",
                        default="")
    parser.add_argument("--microserviceType", help="you service type, \" N \" or \" NATIVE \", NATIVE "
                                                   "means native cloud app",
                        default="NATIVE")
    parser.add_argument("--applicationType",help="application type, default V", default="V")
    parser.add_argument("--pkgVersion", help="the package version of your application, default is timestamp",
                        default=datetime.now().strftime("%Y%m%d%H%M%S"))

    args = vars(parser.parse_args())
    #check the path is an abs path or not, if not, making the path with the current path
    path = args["path"]
    if not os.path.isabs(path):
        basePath = os.path.dirname(os.path.abspath(__name__))
        path = os.path.join(basePath, path)
    if not os.path.exists(path):
        print "[Error], the path: {} is not exist! Please check it".format(path)
        sys.exit()
    applicationName = args["applicationName"]
    if not args["groupName"]:
        args["groupName"] = applicationName
    print repr(args)
    return args

# get the tsf client, when load this script
client = getClient()

if __name__ == "__main__":
    args = argsParser()
    Main(path=args["path"], pkgVersion=args["pkgVersion"], appId=args["appId"], applicationName=args["applicationName"],
         applicationType=args["applicationType"], microserviceType=args["microserviceType"], groupName=args["groupName"])


