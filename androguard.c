/*
Copyright (c) 2015. The Koodous Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
  Changelog:
    - 2016/06/09: Start changelog and add funtions for "filters"
    - 2016/06/16: Hotfix min/max/target sdk version
    - 2016/12/12: Added certificate.not_before and certificate.not_after functions
    - 2017/01/11: Added displayed_version functions
*/

#include <jansson.h>
#include <string.h>


#include <yara/re.h>
#include <yara/modules.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

#define MODULE_NAME androguard


/*
  Permissions struct (combine both)
*/
struct permissions {
  void* permissions;
  void* new_permissions;
};


/*
  Function to detect certificate.subject
*/
define_function(certificate_subject_lookup)
{
  YR_OBJECT* obj = parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;

  val = json_object_get(obj->data, "subjectDN");
  if (val) {
    value = (char *)json_string_value(val);
    if (value) {
      if (yr_re_match(regexp_argument(1), value) > 0) {
        result = 1;
      }
    }
  }

  return_integer(result);
}

/*
  Method to remove colon of a string
*/
void remove_colon(const char* input, char* output) {
  int i, pos_out=0;

  for(i=0;i<strlen(input)+1;++i) {
    if (input[i] != ':') {
      output[pos_out++] = input[i];
    }
  }
}

/*
  Function to detect certificate.not_before (with regex)
*/
define_function(certificate_not_before_lookup_regex)
{
  YR_OBJECT* obj = parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;

  val = json_object_get(obj->data, "not_before");
  if (val) {
    value = (char *)json_string_value(val);
  }

  if (value) {
    if (yr_re_match(regexp_argument(1), value) > 0) {
      result = 1;
    }
  }

  return_integer(result);
}

/*
  Function to detect certificate.not_before (with string)
*/
define_function(certificate_not_before_lookup_string)
{
  YR_OBJECT* obj = parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;
  val = json_object_get(obj->data, "not_before");

  if (val != NULL) {
    value = (char *)json_string_value(val);    
  }

  if (value != NULL) {
    if (strcasecmp(string_argument(1), value) == 0) {
      result = 1;
    }
  }

  return_integer(result);
}

/*
  Function to detect certificate.not_after (with regex)
*/
define_function(certificate_not_after_lookup_regex)
{
  YR_OBJECT* obj = parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;

  val = json_object_get(obj->data, "not_after");
  if (val) {
    value = (char *)json_string_value(val);
  }

  if (value) {
    if (yr_re_match(regexp_argument(1), value) > 0) {
      result = 1;
    }
  }

  return_integer(result);
}

/*
  Function to detect certificate.not_after (with string)
*/
define_function(certificate_not_after_lookup_string)
{
  YR_OBJECT* obj = parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;
  val = json_object_get(obj->data, "not_after");

  if (val != NULL) {
    value = (char *)json_string_value(val);    
  }
  if (value != NULL) {
    if (strcasecmp(string_argument(1), value) == 0) {
      result = 1;
    }
  }
  return_integer(result);
}

/*
  Function to detect certificate.sha1 (with or without colon (:) separators)
*/
define_function(certificate_sha1_lookup)
{
  YR_OBJECT* obj = parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;
  val = json_object_get(obj->data, "sha1");
  char *argument = string_argument(1);
  char *cert_str;
  cert_str = (char*)malloc((strlen(argument)+1)*sizeof(char));

  if (cert_str != NULL) {
    remove_colon(argument, cert_str);
  } else {
    return_integer(result);
  }

  if (val) {
    value = (char *)json_string_value(val);
    if (value) {
      if (strcasecmp(cert_str, value) == 0) {
        result = 1;
      }
    }
    
  }
  free(cert_str);

  return_integer(result);
}

/*
  Function to detect certificate.issuer
*/
define_function(certificate_issuer_lookup)
{
  YR_OBJECT* obj = parent();
  char *value = NULL;
  uint64_t result = 0;
  json_t *val;

  //json_t* mutexes_json = (json_t*) sync_obj->data;
  val = json_object_get(obj->data, "issuerDN");
  if (val) {
    value = (char *)json_string_value(val);
  }

  if (value) {
    if (yr_re_match(regexp_argument(1), value) > 0) {
      result = 1;
    }
  }

  return_integer(result);
}

/*
  Function to detect main_activity
*/
define_function(main_activity_lookup)
{
  YR_OBJECT* obj = get_object(module(), "main_activity");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
    if (yr_re_match(regexp_argument(1), value) > 0) {
      result = 1;
    }
  }
 
  return_integer(result);
}

/*
  Function to detect permissions and new_permissions
*/
define_function(permission_lookup)
{
  YR_OBJECT* obj = get_object(module(), "permission");
  struct permissions *a;

  a = obj->data;
  if (a == NULL) { return_integer(0); }
  
  json_t* list_perms = (json_t*) a->permissions;
  json_t* list_new_perms = (json_t*) a->new_permissions;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list_perms, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }
  //Or try with new_permissions
  if (!result) {
    json_array_foreach(list_new_perms, index, value)
    {
      if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
      {
        result = 1;
        break;
      }
    }
  }
  return_integer(result);
}

/*
  Function to detect activities (with regex)
*/
define_function(activity_lookup_regex)
{
  YR_OBJECT* activity_obj = get_object(module(), "activity");
  json_t* list = (json_t*) activity_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect activities (with string)
*/
define_function(activity_lookup_string)
{
  YR_OBJECT* activity_obj = get_object(module(), "activity");
  json_t* list = (json_t*) activity_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect services (with regex)
*/
define_function(service_lookup_regex)
{
  YR_OBJECT* service_obj = get_object(module(), "service");
  json_t* list = (json_t*) service_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect services (with string)
*/
define_function(service_lookup_string)
{
  YR_OBJECT* service_obj = get_object(module(), "service");
  json_t* list = (json_t*) service_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect filters (with regex)
*/
define_function(filter_lookup_regex)
{
  YR_OBJECT* filter_obj = get_object(module(), "filter");
  json_t* list = (json_t*) filter_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect filters (with string)
*/
define_function(filter_lookup_string)
{
  YR_OBJECT* filter_obj = get_object(module(), "filter");
  json_t* list = (json_t*) filter_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect receivers (with regex)
*/
define_function(receiver_lookup_regex)
{
  YR_OBJECT* receiver_obj = get_object(module(), "receiver");
  json_t* list = (json_t*) receiver_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect receivers (with string)
*/
define_function(receiver_lookup_string)
{
  YR_OBJECT* receiver_obj = get_object(module(), "receiver");
  json_t* list = (json_t*) receiver_obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect displayed version (with regex)
*/
define_function(displayed_version_lookup_regex)
{
  YR_OBJECT* obj = get_object(module(), "displayed_version");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
    if (yr_re_match(regexp_argument(1), value) > 0) {
      result = 1;
    }
  }
 
  return_integer(result);
}

/*
  Function to detect displayed version (with string)
*/
define_function(displayed_version_lookup_string)
{
  YR_OBJECT* obj = get_object(module(), "displayed_version");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
    if (strcasecmp(string_argument(1), value) == 0) {
      result = 1;
    }
  }
 
  return_integer(result);
}


/*
  Function to detect Android version code (with regex)
*/
define_function(version_code_regex)
{
    YR_OBJECT *obj = get_object(module(), "version_code");
    char *value = obj->data;

    return_integer(value && (yr_re_match(regexp_argument(1), value) == 0));
}


/*
  Function to detect Android version code (with string)
*/
define_function(version_code_string)
{
    YR_OBJECT *obj = get_object(module(), "version_code");
    char *value = obj->data;

    return_integer(value && (strcasecmp(string_argument(1), value) == 0));
}

/*
  Function to detect Android version name (with regex)
*/
define_function(version_name_regex)
{
    YR_OBJECT *obj = get_object(module(), "version_name");
    char *value = obj->data;

    return_integer(value && (yr_re_match(regexp_argument(1), value) == 0));
}


/*
  Function to detect Android version name (with string)
*/
define_function(version_name_string)
{
    YR_OBJECT *obj = get_object(module(), "version_name");
    char *value = obj->data;

    return_integer(value && (strcasecmp(string_argument(1), value) == 0));
}


/*
  Function to detect url (with regex)
*/
define_function(url_lookup_regex)
{
  YR_OBJECT* obj = get_object(module(), "url");
  json_t* list = (json_t*) obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (yr_re_match(regexp_argument(1), json_string_value(value)) > 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect url (with string)
*/
define_function(url_lookup_string)
{
  YR_OBJECT* obj = get_object(module(), "url");
  json_t* list = (json_t*) obj->data;

  uint64_t result = 0;
  size_t index;
  json_t* value;

  json_array_foreach(list, index, value)
  {
    if (strcasecmp(string_argument(1), json_string_value(value)) == 0)
    {
      result = 1;
      break;
    }
  }
  return_integer(result);
}

/*
  Function to detect appname (with regex)
*/
define_function(appname_lookup_regex)
{
  YR_OBJECT* obj = get_object(module(), "app_name");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
    if (yr_re_match(regexp_argument(1), value) > 0) {
      result = 1;
    }
  }

  return_integer(result);
}

/*
  Function to detect appname (with string)
*/
define_function(appname_lookup_string)
{
  YR_OBJECT* obj = get_object(module(), "app_name");
  char* value = obj->data;
  uint64_t result = 0;

  if (value) {
    if (strcasecmp(string_argument(1), value) == 0) {
      result = 1;
    }
  }

  return_integer(result);
}

/*
  Function to detect package_name (with regex)
*/
define_function(package_name_lookup_regex)
{
  YR_OBJECT* package_name_obj = get_object(module(), "package_name");
  char* value = package_name_obj->data;
  uint64_t result = 0;

  if (value) {
    if (yr_re_match(regexp_argument(1), value) > 0) {
      result = 1;
    }
  }

  return_integer(result);
}

/*
  Function to detect package_name (wuth string)
*/
define_function(package_name_lookup_string)
{
  YR_OBJECT* package_name_obj = get_object(module(), "package_name");
  char* value = package_name_obj->data;
  uint64_t result = 0;

  if (value) {
    if (strcasecmp(string_argument(1), value) == 0) {
      result = 1;
    }
  }

  return_integer(result);
}

/*
  Declarations
*/
begin_declarations;
  begin_struct("certificate");
    declare_function("issuer", "r", "i", certificate_issuer_lookup);
    declare_function("subject", "r", "i", certificate_subject_lookup);
    declare_function("sha1", "s", "i", certificate_sha1_lookup);
    declare_function("not_after", "r", "i", certificate_not_after_lookup_regex);
    declare_function("not_after", "s", "i", certificate_not_after_lookup_string);
    declare_function("not_before", "r", "i", certificate_not_before_lookup_regex);
    declare_function("not_before", "s", "i", certificate_not_before_lookup_string);
  end_struct("certificate");
  
  declare_integer("min_sdk");
  declare_integer("max_sdk");
  declare_integer("target_sdk");

  declare_function("displayed_version", "r", "i", displayed_version_lookup_regex);
  declare_function("displayed_version", "s", "i", displayed_version_lookup_string);

  declare_function("version_code", "r", "i", version_code_regex);
  declare_function("version_code", "s", "i", version_code_string);

  declare_function("version_name", "r", "i", version_name_regex);
  declare_function("version_name", "s", "i", version_name_string);

  declare_function("url", "r", "i", url_lookup_regex);
  declare_function("url", "s", "i", url_lookup_string);

  declare_function("app_name", "r", "i", appname_lookup_regex);
  declare_function("app_name", "s", "i", appname_lookup_string);

  declare_function("permission", "r", "i", permission_lookup);

  declare_integer("permissions_number");

  declare_function("receiver", "r", "i", receiver_lookup_regex);
  declare_function("receiver", "s", "i", receiver_lookup_string);

  declare_function("activity", "r", "i", activity_lookup_regex);
  declare_function("activity", "s", "i", activity_lookup_string);

  declare_function("main_activity", "r", "i", main_activity_lookup);

  declare_function("service", "r", "i", service_lookup_regex);
  declare_function("service", "s", "i", service_lookup_string);

  declare_function("filter", "r", "i", filter_lookup_regex);  
  declare_function("filter", "s", "i", filter_lookup_string);  

  declare_function("package_name", "r", "i", package_name_lookup_regex);
  declare_function("package_name", "s", "i", package_name_lookup_string);
end_declarations;

/*
  Initialize module
*/
int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

/*
  Finalize module
*/
int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


/*
  Module load
*/
int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  /* Definitions */
  YR_OBJECT* permission_obj = NULL;
  YR_OBJECT* activity_obj = NULL;
  YR_OBJECT* package_name_obj = NULL;
  YR_OBJECT* main_activity_obj = NULL;
  YR_OBJECT* appname_obj = NULL;
  YR_OBJECT* certificate_obj = NULL;
  YR_OBJECT* service_obj = NULL;
  YR_OBJECT* filter_obj = NULL;
  YR_OBJECT* receiver_obj = NULL;
  YR_OBJECT* url_obj = NULL;
  YR_OBJECT* displayed_version_obj = NULL;
  struct permissions *permissions_struct = NULL;

  int version, perms_number;
  json_error_t json_error;
  const char* str_val = NULL;
  json_t* json = NULL;

  /* End definitions */
  if (module_data == NULL)
    return ERROR_SUCCESS;

  json = json_loadb(
      (const char*) module_data,
      module_data_size,
      0,
      &json_error);

  if (json == NULL)
    return ERROR_INVALID_FILE;

  /* Assign each object to their variables */
  package_name_obj = get_object(module_object, "package_name");
  activity_obj = get_object(module_object, "activity");
  main_activity_obj = get_object(module_object, "main_activity");
  permission_obj = get_object(module_object, "permission");
  appname_obj = get_object(module_object, "app_name");
  certificate_obj = get_object(module_object, "certificate");
  service_obj = get_object(module_object, "service");
  filter_obj = get_object(module_object, "filter");
  receiver_obj = get_object(module_object, "receiver");
  url_obj = get_object(module_object, "url");
  displayed_version_obj = get_object(module_object, "displayed_version");


  /* Set SDK versions
     MIN_SDK_VERSION */
  version = 0;
  str_val = json_string_value(json_object_get(json, "min_sdk_version"));
  if (str_val) {
    version = atoi(str_val);
  } else {
    version = json_integer_value(json_object_get(json, "min_sdk_version"));
  }
  set_integer(version, module_object, "min_sdk");

  /* MAX_SDK_VERSION */
  version = 0;
  str_val = json_string_value(json_object_get(json, "max_sdk_version"));
  if (str_val) {
    version = atoi(str_val);
  } else {
    version = json_integer_value(json_object_get(json, "max_sdk_version"));
  }
  set_integer(version, module_object, "max_sdk");

  /* TARGET_SDK_VERSION */
  version = 0;
  str_val = json_string_value(json_object_get(json, "target_sdk_version"));
  if (str_val) {
    version = atoi(str_val);
  } else {
    version = json_integer_value(json_object_get(json, "target_sdk_version"));
  }
  set_integer(version, module_object, "target_sdk");

  /* Now extract other values from JSON */
  certificate_obj->data = json_object_get(json, "certificate");
  activity_obj->data = json_object_get(json, "activities");
  service_obj->data = json_object_get(json, "services");
  filter_obj->data = json_object_get(json, "filters");
  receiver_obj->data = json_object_get(json, "receivers");
  url_obj->data = json_object_get(json, "urls");

  /* Extract main_activity */
  main_activity_obj->data = (char *)json_string_value(
                                    json_object_get(json, "main_activity"));

  /* Extract app_name */
  appname_obj->data = (char *)json_string_value(
                                    json_object_get(json, "app_name"));

  /* Extract displayed_version */
  displayed_version_obj->data = (char *)json_string_value(
                                    json_object_get(json, "displayed_version"));  

  /* Extract package_name */
  package_name_obj->data = (char *)json_string_value(
                                    json_object_get(json, "package_name"));

  /* Permissions */
  permissions_struct = malloc(sizeof(struct permissions));
  permissions_struct->permissions = (void *)json_object_get(json, 
                                                            "permissions");
  permissions_struct->new_permissions = (void *)json_object_get(json, 
                                                            "new_permissions");
  permission_obj->data = permissions_struct;

  /* Permissions number */
  perms_number = json_array_size(permissions_struct->permissions);
  perms_number += json_array_size(permissions_struct->new_permissions);
  set_integer(perms_number, module_object, "permissions_number");

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module)
{
  YR_OBJECT* obj;
  if (module->data != NULL)
    json_decref((json_t*) module->data);

  //Free memory allocated in module load
  obj = get_object(module, "permission");
  if (obj != NULL) {
    free(obj->data);
  }

  return ERROR_SUCCESS;
}
