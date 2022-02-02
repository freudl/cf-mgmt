package user

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/vmwarepivotallabs/cf-mgmt/uaa"
	"github.com/xchapter7x/lo"
)

//SyncSamlUsers
//roleUsers Users currently (actual state) granted the right to do something, e.g. SpaceDeveloper
//uaaUsers Users which are known to UAA
//usersInput Users which must be (de-)authorized (desired state)
func (m *DefaultManager) SyncSamlUsers(roleUsers *RoleUsers, uaaUsers *uaa.Users, usersInput UsersInput) error {
	origin := m.LdapConfig.Origin
	for _, userEmail := range m.unionOfUsersToGrantTo(uaaUsers, usersInput) {
		userList := uaaUsers.GetByName(userEmail)
		if len(userList) == 0 {
			lo.G.Debug("User", userEmail, "doesn't exist in cloud foundry, so creating user")
			if userGUID, err := m.UAAMgr.CreateExternalUser(userEmail, userEmail, userEmail, origin); err != nil {
				lo.G.Error("Unable to create user", userEmail)
				continue
			} else {
				uaaUsers.Add(uaa.User{
					Username:   userEmail,
					Email:      userEmail,
					ExternalID: userEmail,
					Origin:     origin,
					GUID:       userGUID,
				})
				userList = uaaUsers.GetByName(userEmail)
			}
		}
		user := uaaUsers.GetByNameAndOrigin(userEmail, origin)
		if user == nil {
			return fmt.Errorf("Unable to find user %s for origin %s", userEmail, origin)
		}
		if !roleUsers.HasUserForOrigin(userEmail, user.Origin) {
			if err := usersInput.AddUser(usersInput, user.Username, user.GUID); err != nil {
				return errors.Wrap(err, fmt.Sprintf("User %s with origin %s", user.Username, user.Origin))
			}
		} else {
			roleUsers.RemoveUserForOrigin(userEmail, user.Origin)
		}
	}
	return nil
}

func (m *DefaultManager) unionOfUsersToGrantTo(uaaUsers *uaa.Users, usersInput UsersInput) []string {
	result := map[string]interface{}{} //care about keys, only
	for _, uaaUser := range uaaUsers.List() {
		for _, groupName := range usersInput.UniqueUaaGroupNames() {
			if m.userIsMemberOfGroup(uaaUser, groupName) {
				result[uaaUser.Username] = uaaUser
			}
		}
	}

	for _, userEmail := range usersInput.UniqueSamlUsers() {
		_, found := result[userEmail]
		if !found {
			result[userEmail] = userEmail
		}
	}

	keys := make([]string, len(result))
	i := 0
	for k, _ := range result {
		keys[i] = k
		i++
	}

	return keys
}

func (m *DefaultManager) userIsMemberOfGroup(user uaa.User, groupName string) bool {
	for _, group := range user.Groups {
		if group.Display == groupName {
			return true
		}
	}
	return false
}
