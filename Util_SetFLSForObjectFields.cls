/* To easily call this as an execute anonymous scripts remove the method signature and brackets and set these variables as desired.
list<string> sObjects = new list<string>{'account','object2__c'};
list<string> profileNames = new list<string>{'System Administrator','Standard User'};
boolean canView; //set to true or false
boolean canEdit; //set to true or false
boolean doUpdate = false;
list<string> emailRecips = new list<string>{'your_email_here@somewhere.com'};
*/

/**
*@Description sets the permissions on all fields of all given objects for all given profiles to the given true or false values for view and edit. Additionally can be set to 
* rollback changes to only generate the report of what would be modified. Emails logs of proposed and completed changes to addresses specified. Only modififies permissions that
  do not match the new settings so un-needed changes are not performed and could theoretically be called repeatedly to chip away at changes if the overall amount of DML ends up being
  too much for one operation (chunking/limit logic does not currently exist so doing too many changes at once could cause errors).
*@Param sObjects list of sObjects to set permissions for all fields on
*@Param profileNames a list of names of profiles for which to modify the permissions for
*@Param canView set the view permission to true or false for all fields on all provided objects for all provided profiles
*@Param canEdit set the edit permission to true or false for all fields on all provided objects for all provided profiles
*@Param doUpdate should the changes to field level security actually be performed or no? If not the reports for proposed changes and what the results would be are still generated
        and sent because a database.rollback is used to undo the changes.
*@Param emailRecips a list of email addresses to send the results to. If in a sandbox ensure email deliverability is turned on to receive the reports.
**/
public static string setPermissionsOnObjects(list<string> sObjects, list<string> profileNames, boolean canView, boolean canEdit, boolean doUpdate, list<string> emailRecips){
        
    system.debug('\n\n\n----- Setting Permissions for profiles');
    list<FieldPermissions> updatePermissions = new list<FieldPermissions>();
    string csvUpdateString = 'Object Name, Field Name, Profile, Could Read?, Could Edit?, Can Read?, Can Edit, What Changed\n';
    map<Id,Id> profileIdToPermSetIdMap = new map<Id,Id>();
    map<Id,Id> permSetToProfileIdMap = new map<Id,Id>();
    map<Id,String> profileIdToNameMap = new map<Id,String>();

    //Every profile has an underlying permission set. We have to query for that permission set id to make a new field permission as 
    //those are related to permission sets not profiles.
    for(PermissionSet thisPermSet : [Select Id, IsOwnedByProfile, Label, Profile.Name from PermissionSet  where Profile.Name in :profileNames]){
        profileIdToPermSetIdMap.put(thisPermSet.ProfileId,thisPermSet.Id);
        permSetToProfileIdMap.put(thisPermSet.Id,thisPermSet.ProfileId);
    }

    Map<String, Schema.SObjectType> globalDescribe = Schema.getGlobalDescribe();
    Map<String,Profile> profilesMap = new Map<String,Profile>();

    //map of profile id to object type to field name to field permission
    map<id,map<string,map<string,FieldPermissions>>> objectToFieldPermissionsMap = new map<id,map<string,map<string,FieldPermissions>>>();

    for(Profile  thisProfile : [select name, id from Profile where name in :profileNames]){
        profilesMap.put(thisProfile.Name,thisProfile);
        profileIdToNameMap.put(thisProfile.Id,thisProfile.Name);
    }

    List<FieldPermissions> fpList = [SELECT SobjectType, 
                                            Field, 
                                            PermissionsRead, 
                                            PermissionsEdit, 
                                            Parent.ProfileId 
                                    FROM FieldPermissions 
                                    WHERE SobjectType IN :sObjects  and
                                    Parent.Profile.Name IN :profileNames
                                    ORDER By SobjectType];

    for(FieldPermissions thisPerm : fpList){
        //gets map of object types to fields to permission sets for this permission sets profile
        map<string,map<string,FieldPermissions>> profilePerms = objectToFieldPermissionsMap.containsKey(thisPerm.parent.profileId) ?
                                                                objectToFieldPermissionsMap.get(thisPerm.parent.profileId) :
                                                                new map<string,map<string,FieldPermissions>>();
        //gets map of field names for this object to permissions
        map<string,FieldPermissions> objectPerms = profilePerms.containsKey(thisPerm.sObjectType) ?
                                                   profilePerms.get(thisPerm.sObjectType) :
                                                   new map<string,FieldPermissions>();

        //puts this field and its permission into the object permission map
        objectPerms.put(thisPerm.Field,thisPerm);

        //puts this object permission map into the object permissions map
        profilePerms.put(thisPerm.sObjectType,objectPerms);

        //write profile permissions back to profile permissions map
        objectToFieldPermissionsMap.put(thisPerm.parent.profileId,profilePerms);
    }
    system.debug('\n\n\n----- Built Object Permission Map');
    system.debug(objectToFieldPermissionsMap);

    for(string thisObject : sObjects){

        system.debug('\n\n\n------ Setting permissions for ' + thisObject);
        Map<String, Schema.SObjectField> objectFields = globalDescribe.get(thisObject).getDescribe().fields.getMap();

        for(string thisProfile : profileNames){

            Id profileId = profilesMap.get(thisProfile).Id;

            //gets map of object types to fields to permission sets for this permission sets profile
            map<string,map<string,FieldPermissions>> profilePerms = objectToFieldPermissionsMap.containsKey(profileId) ?
            objectToFieldPermissionsMap.get(profileId) :
            new map<string,map<string,FieldPermissions>>();            

            //gets map of field names for this object to permissions
            map<string,FieldPermissions> objectPerms = profilePerms.containsKey(thisObject) ?
            profilePerms.get(thisObject) :
            new map<string,FieldPermissions>();

            system.debug('\n\n\n---- Setting permissions for profile: ' + thisProfile);
            
            Id permissionSetId = profileIdToPermSetIdMap.get(profileId);
            for(Schema.SObjectField thisField : objectFields.values()){
                string fieldName = thisField.getDescribe().getName();
                boolean canPermission = thisField.getDescribe().isPermissionable();

                if(!canPermission) {
                    system.debug('\n\n\n---- Cannot change permissions for field: ' + thisField + '. Skipping');
                    continue;
                }

                string fieldObjectName = thisObject+'.'+fieldName;
                FieldPermissions thisPermission = objectPerms.containsKey(fieldObjectName) ?
                                                  objectPerms.get(fieldObjectName) :
                                                  new FieldPermissions(Field=fieldObjectName,
                                                                       SobjectType=thisObject,
                                                                       ParentId=permissionSetId);

                if(thisPermission.PermissionsRead != canView || thisPermission.PermissionsEdit != canEdit){      
                    system.debug('------------------- Adjusting Permission for field: ' + fieldName); 
                    
                    csvUpdateString += thisObject+','+fieldName+','+thisProfile+','+thisPermission.PermissionsRead+','+thisPermission.PermissionsEdit+','+canView+','+canEdit+',';

                    if(thisPermission.PermissionsRead != canView) csvUpdateString += 'Read Access ';
                    if(thisPermission.PermissionsEdit != canEdit) csvUpdateString += 'Edit Access ';
                    csvUpdateString+='\n';

                    thisPermission.PermissionsRead = canView;
                    thisPermission.PermissionsEdit = canEdit;
                    updatePermissions.add(thisPermission);
                }
            }
        }
    }

    system.debug('\n\n\n----- Ready to update ' + updatePermissions.size() + ' permissions');

    Savepoint sp = Database.setSavepoint();

    string upsertResults = 'Object Name, Field Name, Permission Set Id, Profile Name, Message\n';

    Database.UpsertResult[] results = Database.upsert(updatePermissions, false);

    for(Integer index = 0, size = results.size(); index < size; index++) {
        FieldPermissions thisObj = updatePermissions[index];

        string thisProfileName = profileIdToNameMap.get(permSetToProfileIdMap.get(thisObj.ParentId));
        if(results[index].isSuccess()) {
            if(results[index].isCreated()) {
                upsertResults += thisObj.sObjectType +',' + thisObj.Field +','+ thisObj.ParentId +',' +thisProfileName+',permission was created\n';
            } else {
                upsertResults += thisObj.sObjectType +',' + thisObj.Field +','+ thisObj.ParentId +',' +thisProfileName+',permission was edited\n';
            }
        }
        else {
            upsertResults +=thisObj.sObjectType +',' + thisObj.Field + ','+ thisObj.ParentId +',' +thisProfileName+'ERROR: '+results[index].getErrors()[0].getMessage()+'\n';                
        }
    }
    if(!doUpdate) Database.rollback(sp);

    system.debug('\n\n\n------- Update Results');
    system.debug(upsertResults);

    Messaging.SingleEmailMessage email = new Messaging.SingleEmailMessage();
    email.setToAddresses(emailRecips);    
    email.setSubject('Object Security Update Result');
    
    string emailBody = 'Updated permissions for objects: ' + sObjects + '\n\n';
    emailBody += 'For profiles: ' + profileNames+'\n\n';
    emailBody += 'CSV Update Plan:\n\n\n\n';
    emailBody += csvUpdateString;
    emailBody += '\n\n\n\n';
    emailBody += 'CSV Update Results: \n\n\n\n';
    emailBody += upsertResults;

    email.setPlainTextBody(emailBody);

    list<Messaging.EmailFileAttachment> attachments = new list<Messaging.EmailFileAttachment>();
    Messaging.EmailFileAttachment efa = new Messaging.EmailFileAttachment();
    efa.setFileName('Update Plan.csv');
    efa.setBody(blob.valueOf(csvUpdateString));
    attachments.add(efa);

    Messaging.EmailFileAttachment efa1 = new Messaging.EmailFileAttachment();
    efa1.setFileName('Update Results.csv');
    efa1.setBody(blob.valueOf(upsertResults));
    attachments.add(efa1);

    email.setFileAttachments(attachments);
    Messaging.sendEmail(new Messaging.SingleEmailMessage[] { email });


    return csvUpdateString;