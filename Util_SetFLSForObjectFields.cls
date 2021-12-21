public with sharing class Util_SetFLSForObjectFields {

	// Run this code block below as Anonymous Apex or call method:
	// Util_SetFLSForObjectFields.grantAccessForSystemAdministrator();
	public static void grantAccessForSystemAdministrator() {
		List<String> sObjects = new List<String> {
			'account', 'contact'
		};
		List<String> profileNames = new List<String> {
			'System Administrator'
		};
		boolean canView = true;
		boolean canEdit = true;
		boolean doUpdate = false;
		List<String> emailRecips = new List<String> {
			'ext1324@foss.dk'
		};
		Util_SetFLSForObjectFields.setPermissionsOnObjects(sObjects, profileNames, canView, canEdit, doUpdate, emailRecips);
	}

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
 *@see https://iwritecrappycode.wordpress.com/2021/12/16/bulk-set-field-level-security-on-objects-for-profiles/
 **/
	public static String setPermissionsOnObjects(List<String> sObjects, List<String> profileNames, boolean canView, boolean canEdit, boolean doUpdate, List<String> emailRecips) {
		String csvSep = ',';

		System.debug('\n\n\n----- Setting Permissions for profiles');
		List<FieldPermissions> updatePermissions = new List<FieldPermissions>();
		String csvUpdateString = 'Object Name, Field Name, Field Type, Profile, Could Read?, Could Edit?, Can Read, Can Edit, What Changed\n';
		Map<Id, Id> profileIdToPermSetIdMap = new Map<Id, Id>();
		Map<Id, Id> permSetToProfileIdMap = new Map<Id, Id>();
		Map<Id, String> profileIdToNameMap = new Map<Id, String>();

		// Every profile has an underlying permission set. We have to query for that permission set id to make a new field permission as
		// those are related to permission sets not profiles.
		for (PermissionSet thisPermSet : [SELECT Id, IsOwnedByProfile, Label, Profile.Name FROM PermissionSet WHERE Profile.Name IN :profileNames]) {
			profileIdToPermSetIdMap.put(thisPermSet.ProfileId, thisPermSet.Id);
			permSetToProfileIdMap.put(thisPermSet.Id, thisPermSet.ProfileId);
		}

		Map<String, Schema.SObjectType> globalDescribe = Schema.getGlobalDescribe();
		Map<String, Profile> profilesMap = new Map<String, Profile>();

		// map of profile id to object type to field name to field permission
		Map<Id, Map<String, Map<String, FieldPermissions>>> objectToFieldPermissionsMap = new Map<Id, Map<String, Map<String, FieldPermissions>>>();

		for (Profile thisProfile : [SELECT Name, Id FROM Profile WHERE Name IN :profileNames]) {
			profilesMap.put(thisProfile.Name, thisProfile);
			profileIdToNameMap.put(thisProfile.Id, thisProfile.Name);
		}

		List<FieldPermissions> fpList = [SELECT SobjectType, Field, PermissionsRead, PermissionsEdit, Parent.ProfileId
										 FROM FieldPermissions
										 WHERE SobjectType IN : sObjects
										 AND Parent.Profile.Name IN : profileNames
										 ORDER BY SobjectType];

		for (FieldPermissions thisPerm : fpList) {
			// gets map of object types to fields to permission sets for this permission sets profile
			Map<String, Map<String, FieldPermissions>> profilePerms = objectToFieldPermissionsMap.containsKey(thisPerm.parent.profileId) ?
																	  objectToFieldPermissionsMap.get(thisPerm.parent.profileId) :
																	  new Map<String, Map<String, FieldPermissions>>();
			// gets map of field names for this object to permissions
			Map<String, FieldPermissions> objectPerms = profilePerms.containsKey(thisPerm.sObjectType) ?
														profilePerms.get(thisPerm.sObjectType) :
														new Map<String, FieldPermissions>();

			// puts this field and its permission into the object permission map
			objectPerms.put(thisPerm.Field, thisPerm);

			// puts this object permission map into the object permissions map
			profilePerms.put(thisPerm.sObjectType, objectPerms);

			// write profile permissions back to profile permissions map
			objectToFieldPermissionsMap.put(thisPerm.parent.profileId, profilePerms);
		}

		System.debug('\n\n\n----- Built Object Permission Map');
		// System.debug(objectToFieldPermissionsMap);

		for (String thisObject : sObjects) {

			System.debug('\n\n\n------ Setting permissions for ' + thisObject);
			Map<String, Schema.SObjectField> objectFields = globalDescribe.get(thisObject).getDescribe().fields.getMap();

			for (String thisProfile : profileNames) {

				Id profileId = profilesMap.get(thisProfile).Id;

				// gets map of object types to fields to permission sets for this permission sets profile
				Map<String, Map<String, FieldPermissions>> profilePerms = objectToFieldPermissionsMap.containsKey(profileId) ?
																		  objectToFieldPermissionsMap.get(profileId) :
																		  new Map<String, Map<String, FieldPermissions>>();

				// gets map of field names for this object to permissions
				Map<String, FieldPermissions> objectPerms = profilePerms.containsKey(thisObject) ?
															profilePerms.get(thisObject) :
															new Map<String, FieldPermissions>();

				System.debug('\n\n\n---- Setting permissions for profile: ' + thisProfile);

				Id permissionSetId = profileIdToPermSetIdMap.get(profileId);

				for (Schema.SObjectField thisField : objectFields.values()) {
					String fieldName = thisField.getDescribe().getName();
					String fieldType = thisField.getDescribe().getType().name();
					Boolean isFormula = thisField.getDescribe().isCalculated();
					boolean canPermission = thisField.getDescribe().isPermissionable();

					if (!canPermission) {
						System.debug('\n\n\n---- Cannot change permissions for field: ' + thisField + '. Skipping');
						continue;
					}

					if (isFormula) {
						fieldType = 'Formula(' + fieldType + ')';
					}

					String fieldObjectName = thisObject + '.' + fieldName;
					FieldPermissions thisPermission = objectPerms.containsKey(fieldObjectName) ?
													  objectPerms.get(fieldObjectName) :
													  new FieldPermissions(Field = fieldObjectName,
																		   SobjectType = thisObject,
																		   ParentId = permissionSetId);

					if (thisPermission.PermissionsRead != canView || thisPermission.PermissionsEdit != canEdit) {
						System.debug('------------------- Adjusting Permission for field: ' + fieldName);

						Boolean wasReadable = thisPermission.PermissionsRead;
						Boolean wasEditable = thisPermission.PermissionsEdit;

						String whatChanged = '';

						// View
						if (thisPermission.PermissionsRead != canView) {
							whatChanged += 'Read Access ';
						}

						thisPermission.PermissionsRead = canView;

						// Edit
						if (!isFormula) {
							if (thisPermission.PermissionsEdit != canEdit) {
								whatChanged += 'Edit Access ';
							}

							thisPermission.PermissionsEdit = canEdit;

						} else {
							thisPermission.PermissionsEdit = false;
							whatChanged += 'Formula is ReadOnly ';
						}

						csvUpdateString += thisObject + csvSep + fieldName + csvSep + fieldType + csvSep + thisProfile + csvSep + wasReadable + csvSep + wasEditable + csvSep + thisPermission.PermissionsRead + csvSep + thisPermission.PermissionsEdit + csvSep + whatChanged;
						csvUpdateString += '\n';

						updatePermissions.add(thisPermission);
					}
				}
			}
		}

		System.debug('\n\n\n----- Ready to update ' + updatePermissions.size() + ' permissions');

		Savepoint sp = Database.setSavepoint();

		String upsertResults = 'Object Name, Field Name, Permission Set Id, Profile Name, Message\n';

		Database.UpsertResult[] results = Database.upsert(updatePermissions, false);

		for (Integer index = 0, size = results.size(); index < size; index++) {
			FieldPermissions thisObj = updatePermissions[index];

			String thisProfileName = profileIdToNameMap.get(permSetToProfileIdMap.get(thisObj.ParentId));

			if (results[index].isSuccess()) {
				if (results[index].isCreated()) {
					upsertResults += thisObj.sObjectType + csvSep + thisObj.Field + csvSep + thisObj.ParentId + csvSep + thisProfileName + csvSep + 'permission was created\n';
				} else {
					upsertResults += thisObj.sObjectType + csvSep + thisObj.Field + csvSep + thisObj.ParentId + csvSep + thisProfileName + csvSep + 'permission was edited\n';
				}
			}
			else {
				upsertResults += thisObj.sObjectType + csvSep + thisObj.Field + csvSep + thisObj.ParentId + csvSep + thisProfileName + csvSep + 'ERROR: ' + results[index].getErrors()[0].getMessage() + '\n';
			}
		}

		if (!doUpdate) Database.rollback(sp);

		// System.debug('\n\n\n------- Update Results');
		// System.debug(upsertResults);

		ID jobID = System.enqueueJob(new sendEmailAsync(csvUpdateString, emailRecips, sObjects, profileNames, upsertResults, doUpdate));

		return csvUpdateString;
	}

	public class sendEmailAsync implements Queueable {
		String csvUpdateString;
		List<String> emailRecips;
		List<String> sObjects;
		List<String> profileNames;
		String upsertResults;
		Boolean doUpdate;

		sendEmailAsync(String csvUpdateString, List<String> emailRecips, List<String> sObjects, List<String> profileNames, String upsertResults, Boolean doUpdate) {
			this.csvUpdateString = csvUpdateString;
			this.emailRecips = emailRecips;
			this.sObjects = sObjects;
			this.profileNames = profileNames;
			this.upsertResults = upsertResults;
			this.doUpdate = doUpdate;
		}

		public void execute(QueueableContext context) {
			Messaging.SingleEmailMessage emailMessage = new Messaging.SingleEmailMessage();
			emailMessage.setToAddresses(emailRecips);
			emailMessage.setSubject('Object Security Update Result');

			String emailBody = '';
			if (!doUpdate) {
				emailBody += '⚠️SIMULATION (no changes are made)⚠️\n\n';
			}
			emailBody += 'Updated permissions for objects: ' + sObjects + '\n';
			emailBody += 'For profiles: ' + profileNames + '\n\n';
			emailBody += 'See attachemnts for details.';
			// emailBody += 'CSV Update Plan:\n\n\n\n';
			// emailBody += csvUpdateString;
			// emailBody += '\n\n\n\n';
			// emailBody += 'CSV Update Results: \n\n\n\n';
			// emailBody += upsertResults;

			emailMessage.setPlainTextBody(emailBody);

			List<Messaging.EmailFileAttachment> attachments = new List<Messaging.EmailFileAttachment>();
			Messaging.EmailFileAttachment efa = new Messaging.EmailFileAttachment();
			efa.setFileName('Update Plan.csv');
			efa.setBody(blob.valueOf(csvUpdateString));
			attachments.add(efa);

			Messaging.EmailFileAttachment efa1 = new Messaging.EmailFileAttachment();
			efa1.setFileName('Update Results.csv');
			efa1.setBody(blob.valueOf(upsertResults));
			attachments.add(efa1);

			emailMessage.setFileAttachments(attachments);

			Messaging.sendEmail(new Messaging.SingleEmailMessage[] { emailMessage });
		}

	}
    
}