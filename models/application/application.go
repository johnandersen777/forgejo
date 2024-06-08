// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package application

import (
	"context"
	"fmt"
	"strings"

	actions_model "code.gitea.io/gitea/models/actions"
	"code.gitea.io/gitea/models/db"
	"code.gitea.io/gitea/models/perm"
	repo_model "code.gitea.io/gitea/models/repo"
	secret_model "code.gitea.io/gitea/models/secret"
	"code.gitea.io/gitea/models/unit"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/util"

	"xorm.io/builder"
)

// ________                            .__                __  .__
// \_____  \_______  _________    ____ |__|____________ _/  |_|__| ____   ____
//  /   |   \_  __ \/ ___\__  \  /    \|  \___   /\__  \\   __\  |/  _ \ /    \
// /    |    \  | \/ /_/  > __ \|   |  \  |/    /  / __ \|  | |  (  <_> )   |  \
// \_______  /__|  \___  (____  /___|  /__/_____ \(____  /__| |__|\____/|___|  /
//         \/     /_____/     \/     \/         \/     \/                    \/

// ErrApplicationNotExist represents a "ApplicationNotExist" kind of error.
type ErrApplicationNotExist struct {
	ID   int64
	Name string
}

// IsErrApplicationNotExist checks if an error is a ErrApplicationNotExist.
func IsErrApplicationNotExist(err error) bool {
	_, ok := err.(ErrApplicationNotExist)
	return ok
}

func (err ErrApplicationNotExist) Error() string {
	return fmt.Sprintf("application does not exist [id: %d, name: %s]", err.ID, err.Name)
}

func (err ErrApplicationNotExist) Unwrap() error {
	return util.ErrNotExist
}

// ErrLastApplicationOwner represents a "LastApplicationOwner" kind of error.
type ErrLastApplicationOwner struct {
	UID int64
}

// IsErrLastApplicationOwner checks if an error is a ErrLastApplicationOwner.
func IsErrLastApplicationOwner(err error) bool {
	_, ok := err.(ErrLastApplicationOwner)
	return ok
}

func (err ErrLastApplicationOwner) Error() string {
	return fmt.Sprintf("user is the last member of owner team [uid: %d]", err.UID)
}

// ErrUserNotAllowedCreateApplication represents a "UserNotAllowedCreateApplication" kind of error.
type ErrUserNotAllowedCreateApplication struct{}

// IsErrUserNotAllowedCreateApplication checks if an error is an ErrUserNotAllowedCreateApplication.
func IsErrUserNotAllowedCreateApplication(err error) bool {
	_, ok := err.(ErrUserNotAllowedCreateApplication)
	return ok
}

func (err ErrUserNotAllowedCreateApplication) Error() string {
	return "user is not allowed to create applications"
}

func (err ErrUserNotAllowedCreateApplication) Unwrap() error {
	return util.ErrPermissionDenied
}

// Application represents an application
type Application user_model.User

// ApplicationFromUser converts user to application
func ApplicationFromUser(user *user_model.User) *Application {
	return (*Application)(user)
}

// TableName represents the real table name of Application
func (Application) TableName() string {
	return "user"
}

// IsOwnedBy returns true if given user is in the owner team.
func (application *Application) IsOwnedBy(ctx context.Context, uid int64) (bool, error) {
	return IsApplicationOwner(ctx, application.ID, uid)
}

// IsApplicationAdmin returns true if given user is in the owner team or an admin team.
func (application *Application) IsApplicationAdmin(ctx context.Context, uid int64) (bool, error) {
	return IsApplicationAdmin(ctx, application.ID, uid)
}

// IsApplicationMember returns true if given user is member of application.
func (application *Application) IsApplicationMember(ctx context.Context, uid int64) (bool, error) {
	return IsApplicationMember(ctx, application.ID, uid)
}

// CanCreateApplicationRepo returns true if given user can create repo in application
func (application *Application) CanCreateApplicationRepo(ctx context.Context, uid int64) (bool, error) {
	return CanCreateApplicationRepo(ctx, application.ID, uid)
}

// GetTeam returns named team of application.
func (application *Application) GetTeam(ctx context.Context, name string) (*Team, error) {
	return GetTeam(ctx, application.ID, name)
}

// GetOwnerTeam returns owner team of application.
func (application *Application) GetOwnerTeam(ctx context.Context) (*Team, error) {
	return application.GetTeam(ctx, OwnerTeamName)
}

// FindApplicationTeams returns all teams of a given application
func FindApplicationTeams(ctx context.Context, applicationID int64) ([]*Team, error) {
	var teams []*Team
	return teams, db.GetEngine(ctx).
		Where("application_id=?", applicationID).
		OrderBy("CASE WHEN name LIKE '" + OwnerTeamName + "' THEN '' ELSE name END").
		Find(&teams)
}

// LoadTeams load teams if not loaded.
func (application *Application) LoadTeams(ctx context.Context) ([]*Team, error) {
	return FindApplicationTeams(ctx, application.ID)
}

// GetMembers returns all members of application.
func (application *Application) GetMembers(ctx context.Context) (user_model.UserList, map[int64]bool, error) {
	return FindApplicationMembers(ctx, &FindApplicationMembersOpts{
		ApplicationID: application.ID,
	})
}

// HasMemberWithUserID returns true if user with userID is part of the u applicationanisation.
func (application *Application) HasMemberWithUserID(ctx context.Context, userID int64) bool {
	return application.hasMemberWithUserID(ctx, userID)
}

func (application *Application) hasMemberWithUserID(ctx context.Context, userID int64) bool {
	isMember, err := IsApplicationMember(ctx, application.ID, userID)
	if err != nil {
		log.Error("IsApplicationMember: %v", err)
		return false
	}
	return isMember
}

// AvatarLink returns the full avatar link with http host
func (application *Application) AvatarLink(ctx context.Context) string {
	return application.AsUser().AvatarLink(ctx)
}

// HTMLURL returns the application's full link.
func (application *Application) HTMLURL() string {
	return application.AsUser().HTMLURL()
}

// ApplicationanisationLink returns the application sub page link.
func (application *Application) ApplicationanisationLink() string {
	return application.AsUser().ApplicationanisationLink()
}

// ShortName ellipses username to length
func (application *Application) ShortName(length int) string {
	return application.AsUser().ShortName(length)
}

// HomeLink returns the user or application home page link.
func (application *Application) HomeLink() string {
	return application.AsUser().HomeLink()
}

// CanCreateRepo returns if user login can create a repository
// NOTE: functions calling this assume a failure due to repository count limit; if new checks are added, those functions should be revised
func (application *Application) CanCreateRepo() bool {
	return application.AsUser().CanCreateRepo()
}

// FindApplicationMembersOpts represensts find application members conditions
type FindApplicationMembersOpts struct {
	db.ListOptions
	ApplicationID int64
	PublicOnly    bool
}

// CountApplicationMembers counts the application's members
func CountApplicationMembers(ctx context.Context, opts *FindApplicationMembersOpts) (int64, error) {
	sess := db.GetEngine(ctx).Where("application_id=?", opts.ApplicationID)
	if opts.PublicOnly {
		sess.And("is_public = ?", true)
	}
	return sess.Count(new(ApplicationUser))
}

// FindApplicationMembers loads application members according conditions
func FindApplicationMembers(ctx context.Context, opts *FindApplicationMembersOpts) (user_model.UserList, map[int64]bool, error) {
	ous, err := GetApplicationUsersByApplicationID(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	ids := make([]int64, len(ous))
	idsIsPublic := make(map[int64]bool, len(ous))
	for i, ou := range ous {
		ids[i] = ou.UID
		idsIsPublic[ou.UID] = ou.IsPublic
	}

	users, err := user_model.GetUsersByIDs(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	return users, idsIsPublic, nil
}

// AsUser returns the application as user object
func (application *Application) AsUser() *user_model.User {
	return (*user_model.User)(application)
}

// DisplayName returns full name if it's not empty,
// returns username otherwise.
func (application *Application) DisplayName() string {
	return application.AsUser().DisplayName()
}

// CustomAvatarRelativePath returns user custom avatar relative path.
func (application *Application) CustomAvatarRelativePath() string {
	return application.Avatar
}

// UnitPermission returns unit permission
func (application *Application) UnitPermission(ctx context.Context, doer *user_model.User, unitType unit.Type) perm.AccessMode {
	if doer != nil {
		teams, err := GetUserApplicationTeams(ctx, application.ID, doer.ID)
		if err != nil {
			log.Error("GetUserApplicationTeams: %v", err)
			return perm.AccessModeNone
		}

		if err := teams.LoadUnits(ctx); err != nil {
			log.Error("LoadUnits: %v", err)
			return perm.AccessModeNone
		}

		if len(teams) > 0 {
			return teams.UnitMaxAccess(unitType)
		}
	}

	if application.Visibility.IsPublic() {
		return perm.AccessModeRead
	}

	return perm.AccessModeNone
}

// CreateApplication creates record of a new application.
func CreateApplication(ctx context.Context, application *Application, owner *user_model.User) (err error) {
	if !owner.CanCreateApplication() {
		return ErrUserNotAllowedCreateApplication{}
	}

	if err = user_model.IsUsableUsername(application.Name); err != nil {
		return err
	}

	isExist, err := user_model.IsUserExist(ctx, 0, application.Name)
	if err != nil {
		return err
	} else if isExist {
		return user_model.ErrUserAlreadyExist{Name: application.Name}
	}

	application.LowerName = strings.ToLower(application.Name)
	if application.Rands, err = user_model.GetUserSalt(); err != nil {
		return err
	}
	if application.Salt, err = user_model.GetUserSalt(); err != nil {
		return err
	}
	application.UseCustomAvatar = true
	application.MaxRepoCreation = -1
	application.NumTeams = 1
	application.NumMembers = 1
	application.Type = user_model.UserTypeApplication

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	if err = user_model.DeleteUserRedirect(ctx, application.Name); err != nil {
		return err
	}

	if err = db.Insert(ctx, application); err != nil {
		return fmt.Errorf("insert application: %w", err)
	}
	if err = user_model.GenerateRandomAvatar(ctx, application.AsUser()); err != nil {
		return fmt.Errorf("generate random avatar: %w", err)
	}

	// Add initial creator to application and owner team.
	if err = db.Insert(ctx, &ApplicationUser{
		UID:           owner.ID,
		ApplicationID: application.ID,
		IsPublic:      setting.Service.DefaultApplicationMemberVisible,
	}); err != nil {
		return fmt.Errorf("insert application-user relation: %w", err)
	}

	// Create default owner team.
	t := &Team{
		ApplicationID:            application.ID,
		LowerName:                strings.ToLower(OwnerTeamName),
		Name:                     OwnerTeamName,
		AccessMode:               perm.AccessModeOwner,
		NumMembers:               1,
		IncludesAllRepositories:  true,
		CanCreateApplicationRepo: true,
	}
	if err = db.Insert(ctx, t); err != nil {
		return fmt.Errorf("insert owner team: %w", err)
	}

	// insert units for team
	units := make([]TeamUnit, 0, len(unit.AllRepoUnitTypes))
	for _, tp := range unit.AllRepoUnitTypes {
		up := perm.AccessModeOwner
		if tp == unit.TypeExternalTracker || tp == unit.TypeExternalWiki {
			up = perm.AccessModeRead
		}
		units = append(units, TeamUnit{
			ApplicationID: application.ID,
			TeamID:        t.ID,
			Type:          tp,
			AccessMode:    up,
		})
	}

	if err = db.Insert(ctx, &units); err != nil {
		return err
	}

	if err = db.Insert(ctx, &TeamUser{
		UID:           owner.ID,
		ApplicationID: application.ID,
		TeamID:        t.ID,
	}); err != nil {
		return fmt.Errorf("insert team-user relation: %w", err)
	}

	return committer.Commit()
}

// GetApplicationByName returns application by given name.
func GetApplicationByName(ctx context.Context, name string) (*Application, error) {
	if len(name) == 0 {
		return nil, ErrApplicationNotExist{0, name}
	}
	u := &Application{
		LowerName: strings.ToLower(name),
		Type:      user_model.UserTypeApplication,
	}
	has, err := db.GetEngine(ctx).Get(u)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, ErrApplicationNotExist{0, name}
	}
	return u, nil
}

// DeleteApplication deletes models associated to an application.
func DeleteApplication(ctx context.Context, application *Application) error {
	if application.Type != user_model.UserTypeApplication {
		return fmt.Errorf("%s is a user not an application", application.Name)
	}

	if err := db.DeleteBeans(ctx,
		&Team{ApplicationID: application.ID},
		&ApplicationUser{ApplicationID: application.ID},
		&TeamUser{ApplicationID: application.ID},
		&TeamUnit{ApplicationID: application.ID},
		&TeamInvite{ApplicationID: application.ID},
		&secret_model.Secret{OwnerID: application.ID},
		&actions_model.ActionRunner{OwnerID: application.ID},
		&actions_model.ActionRunnerToken{OwnerID: application.ID},
	); err != nil {
		return fmt.Errorf("DeleteBeans: %w", err)
	}

	if _, err := db.GetEngine(ctx).ID(application.ID).Delete(new(user_model.User)); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}

	return nil
}

// GetApplicationUserMaxAuthorizeLevel returns highest authorize level of user in an application
func (application *Application) GetApplicationUserMaxAuthorizeLevel(ctx context.Context, uid int64) (perm.AccessMode, error) {
	var authorize perm.AccessMode
	_, err := db.GetEngine(ctx).
		Select("max(team.authorize)").
		Table("team").
		Join("INNER", "team_user", "team_user.team_id = team.id").
		Where("team_user.uid = ?", uid).
		And("team_user.application_id = ?", application.ID).
		Get(&authorize)
	return authorize, err
}

// GetUsersWhoCanCreateApplicationRepo returns users which are able to create repo in application
func GetUsersWhoCanCreateApplicationRepo(ctx context.Context, applicationID int64) (map[int64]*user_model.User, error) {
	// Use a map, in order to de-duplicate users.
	users := make(map[int64]*user_model.User)
	return users, db.GetEngine(ctx).
		Join("INNER", "`team_user`", "`team_user`.uid=`user`.id").
		Join("INNER", "`team`", "`team`.id=`team_user`.team_id").
		Where(builder.Eq{"team.can_create_application_repo": true}.Or(builder.Eq{"team.authorize": perm.AccessModeOwner})).
		And("team_user.application_id = ?", applicationID).Find(&users)
}

// SearchApplicationsOptions options to filter applications
type SearchApplicationsOptions struct {
	db.ListOptions
	All bool
}

// FindApplicationOptions finds applications options
type FindApplicationOptions struct {
	db.ListOptions
	UserID         int64
	IncludePrivate bool
}

func queryUserApplicationIDs(userID int64, includePrivate bool) *builder.Builder {
	cond := builder.Eq{"uid": userID}
	if !includePrivate {
		cond["is_public"] = true
	}
	return builder.Select("application_id").From("application_user").Where(cond)
}

func (opts FindApplicationOptions) ToConds() builder.Cond {
	var cond builder.Cond = builder.Eq{"`user`.`type`": user_model.UserTypeApplication}
	if opts.UserID > 0 {
		cond = cond.And(builder.In("`user`.`id`", queryUserApplicationIDs(opts.UserID, opts.IncludePrivate)))
	}
	if !opts.IncludePrivate {
		cond = cond.And(builder.Eq{"`user`.visibility": structs.VisibleTypePublic})
	}
	return cond
}

func (opts FindApplicationOptions) ToOrders() string {
	return "`user`.name ASC"
}

// HasApplicationOrUserVisible tells if the given user can see the given application or user
func HasApplicationOrUserVisible(ctx context.Context, applicationOrUser, user *user_model.User) bool {
	// If user is nil, it's an anonymous user/request.
	// The Ghost user is handled like an anonymous user.
	if user == nil || user.IsGhost() {
		return applicationOrUser.Visibility == structs.VisibleTypePublic
	}

	if user.IsAdmin || applicationOrUser.ID == user.ID {
		return true
	}

	if (applicationOrUser.Visibility == structs.VisibleTypePrivate || user.IsRestricted) && !ApplicationFromUser(applicationOrUser).hasMemberWithUserID(ctx, user.ID) {
		return false
	}
	return true
}

// HasApplicationsVisible tells if the given user can see at least one of the applications provided
func HasApplicationsVisible(ctx context.Context, applications []*Application, user *user_model.User) bool {
	if len(applications) == 0 {
		return false
	}

	for _, application := range applications {
		if HasApplicationOrUserVisible(ctx, application.AsUser(), user) {
			return true
		}
	}
	return false
}

// GetApplicationsCanCreateRepoByUserID returns a list of applications where given user ID
// are allowed to create repos.
func GetApplicationsCanCreateRepoByUserID(ctx context.Context, userID int64) ([]*Application, error) {
	applications := make([]*Application, 0, 10)

	return applications, db.GetEngine(ctx).Where(builder.In("id", builder.Select("`user`.id").From("`user`").
		Join("INNER", "`team_user`", "`team_user`.application_id = `user`.id").
		Join("INNER", "`team`", "`team`.id = `team_user`.team_id").
		Where(builder.Eq{"`team_user`.uid": userID}).
		And(builder.Eq{"`team`.authorize": perm.AccessModeOwner}.Or(builder.Eq{"`team`.can_create_application_repo": true})))).
		Asc("`user`.name").
		Find(&applications)
}

// GetApplicationUsersByApplicationID returns all application-user relations by application ID.
func GetApplicationUsersByApplicationID(ctx context.Context, opts *FindApplicationMembersOpts) ([]*ApplicationUser, error) {
	sess := db.GetEngine(ctx).Where("application_id=?", opts.ApplicationID)
	if opts.PublicOnly {
		sess.And("is_public = ?", true)
	}
	if opts.ListOptions.PageSize > 0 {
		sess = db.SetSessionPagination(sess, opts)

		ous := make([]*ApplicationUser, 0, opts.PageSize)
		return ous, sess.Find(&ous)
	}

	var ous []*ApplicationUser
	return ous, sess.Find(&ous)
}

// ChangeApplicationUserStatus changes public or private membership status.
func ChangeApplicationUserStatus(ctx context.Context, applicationID, uid int64, public bool) error {
	ou := new(ApplicationUser)
	has, err := db.GetEngine(ctx).
		Where("uid=?", uid).
		And("application_id=?", applicationID).
		Get(ou)
	if err != nil {
		return err
	} else if !has {
		return nil
	}

	ou.IsPublic = public
	_, err = db.GetEngine(ctx).ID(ou.ID).Cols("is_public").Update(ou)
	return err
}

// AddApplicationUser adds new user to given application.
func AddApplicationUser(ctx context.Context, applicationID, uid int64) error {
	isAlreadyMember, err := IsApplicationMember(ctx, applicationID, uid)
	if err != nil || isAlreadyMember {
		return err
	}

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	// check in transaction
	isAlreadyMember, err = IsApplicationMember(ctx, applicationID, uid)
	if err != nil || isAlreadyMember {
		return err
	}

	ou := &ApplicationUser{
		UID:           uid,
		ApplicationID: applicationID,
		IsPublic:      setting.Service.DefaultApplicationMemberVisible,
	}

	if err := db.Insert(ctx, ou); err != nil {
		return err
	} else if _, err = db.Exec(ctx, "UPDATE `user` SET num_members = num_members + 1 WHERE id = ?", applicationID); err != nil {
		return err
	}

	return committer.Commit()
}

// GetApplicationByID returns the user object by given ID if exists.
func GetApplicationByID(ctx context.Context, id int64) (*Application, error) {
	u := new(Application)
	has, err := db.GetEngine(ctx).ID(id).Get(u)
	if err != nil {
		return nil, err
	} else if !has {
		return nil, user_model.ErrUserNotExist{
			UID: id,
		}
	}
	return u, nil
}

// RemoveApplicationRepo removes all team-repository relations of application.
func RemoveApplicationRepo(ctx context.Context, applicationID, repoID int64) error {
	teamRepos := make([]*TeamRepo, 0, 10)
	e := db.GetEngine(ctx)
	if err := e.Find(&teamRepos, &TeamRepo{ApplicationID: applicationID, RepoID: repoID}); err != nil {
		return err
	}

	if len(teamRepos) == 0 {
		return nil
	}

	if _, err := e.Delete(&TeamRepo{
		ApplicationID: applicationID,
		RepoID:        repoID,
	}); err != nil {
		return err
	}

	teamIDs := make([]int64, len(teamRepos))
	for i, teamRepo := range teamRepos {
		teamIDs[i] = teamRepo.TeamID
	}

	_, err := e.Decr("num_repos").In("id", teamIDs).Update(new(Team))
	return err
}

func (application *Application) getUserTeams(ctx context.Context, userID int64, cols ...string) ([]*Team, error) {
	teams := make([]*Team, 0, application.NumTeams)
	return teams, db.GetEngine(ctx).
		Where("`team_user`.application_id = ?", application.ID).
		Join("INNER", "team_user", "`team_user`.team_id = team.id").
		Join("INNER", "`user`", "`user`.id=team_user.uid").
		And("`team_user`.uid = ?", userID).
		Asc("`user`.name").
		Cols(cols...).
		Find(&teams)
}

func (application *Application) getUserTeamIDs(ctx context.Context, userID int64) ([]int64, error) {
	teamIDs := make([]int64, 0, application.NumTeams)
	return teamIDs, db.GetEngine(ctx).
		Table("team").
		Cols("team.id").
		Where("`team_user`.application_id = ?", application.ID).
		Join("INNER", "team_user", "`team_user`.team_id = team.id").
		And("`team_user`.uid = ?", userID).
		Find(&teamIDs)
}

// TeamsWithAccessToRepo returns all teams that have given access level to the repository.
func (application *Application) TeamsWithAccessToRepo(ctx context.Context, repoID int64, mode perm.AccessMode) ([]*Team, error) {
	return GetTeamsWithAccessToRepo(ctx, application.ID, repoID, mode)
}

// GetUserTeamIDs returns of all team IDs of the application that user is member of.
func (application *Application) GetUserTeamIDs(ctx context.Context, userID int64) ([]int64, error) {
	return application.getUserTeamIDs(ctx, userID)
}

// GetUserTeams returns all teams that belong to user,
// and that the user has joined.
func (application *Application) GetUserTeams(ctx context.Context, userID int64) ([]*Team, error) {
	return application.getUserTeams(ctx, userID)
}

// AccessibleReposEnvironment operations involving the repositories that are
// accessible to a particular user
type AccessibleReposEnvironment interface {
	CountRepos() (int64, error)
	RepoIDs(page, pageSize int) ([]int64, error)
	Repos(page, pageSize int) (repo_model.RepositoryList, error)
	MirrorRepos() (repo_model.RepositoryList, error)
	AddKeyword(keyword string)
	SetSort(db.SearchOrderBy)
}

type accessibleReposEnv struct {
	application *Application
	user        *user_model.User
	team        *Team
	teamIDs     []int64
	ctx         context.Context
	keyword     string
	orderBy     db.SearchOrderBy
}

// AccessibleReposEnv builds an AccessibleReposEnvironment for the repositories in `application`
// that are accessible to the specified user.
func AccessibleReposEnv(ctx context.Context, application *Application, userID int64) (AccessibleReposEnvironment, error) {
	var user *user_model.User

	if userID > 0 {
		u, err := user_model.GetUserByID(ctx, userID)
		if err != nil {
			return nil, err
		}
		user = u
	}

	teamIDs, err := application.getUserTeamIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &accessibleReposEnv{
		application: application,
		user:        user,
		teamIDs:     teamIDs,
		ctx:         ctx,
		orderBy:     db.SearchOrderByRecentUpdated,
	}, nil
}

// AccessibleTeamReposEnv an AccessibleReposEnvironment for the repositories in `application`
// that are accessible to the specified team.
func (application *Application) AccessibleTeamReposEnv(ctx context.Context, team *Team) AccessibleReposEnvironment {
	return &accessibleReposEnv{
		application: application,
		team:        team,
		ctx:         ctx,
		orderBy:     db.SearchOrderByRecentUpdated,
	}
}

func (env *accessibleReposEnv) cond() builder.Cond {
	cond := builder.NewCond()
	if env.team != nil {
		cond = cond.And(builder.Eq{"team_repo.team_id": env.team.ID})
	} else {
		if env.user == nil || !env.user.IsRestricted {
			cond = cond.Or(builder.Eq{
				"`repository`.owner_id":   env.application.ID,
				"`repository`.is_private": false,
			})
		}
		if len(env.teamIDs) > 0 {
			cond = cond.Or(builder.In("team_repo.team_id", env.teamIDs))
		}
	}
	if env.keyword != "" {
		cond = cond.And(builder.Like{"`repository`.lower_name", strings.ToLower(env.keyword)})
	}
	return cond
}

func (env *accessibleReposEnv) CountRepos() (int64, error) {
	repoCount, err := db.GetEngine(env.ctx).
		Join("INNER", "team_repo", "`team_repo`.repo_id=`repository`.id").
		Where(env.cond()).
		Distinct("`repository`.id").
		Count(&repo_model.Repository{})
	if err != nil {
		return 0, fmt.Errorf("count user repositories in application: %w", err)
	}
	return repoCount, nil
}

func (env *accessibleReposEnv) RepoIDs(page, pageSize int) ([]int64, error) {
	if page <= 0 {
		page = 1
	}

	repoIDs := make([]int64, 0, pageSize)
	return repoIDs, db.GetEngine(env.ctx).
		Table("repository").
		Join("INNER", "team_repo", "`team_repo`.repo_id=`repository`.id").
		Where(env.cond()).
		GroupBy("`repository`.id,`repository`."+strings.Fields(string(env.orderBy))[0]).
		OrderBy(string(env.orderBy)).
		Limit(pageSize, (page-1)*pageSize).
		Cols("`repository`.id").
		Find(&repoIDs)
}

func (env *accessibleReposEnv) Repos(page, pageSize int) (repo_model.RepositoryList, error) {
	repoIDs, err := env.RepoIDs(page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("GetUserRepositoryIDs: %w", err)
	}

	repos := make([]*repo_model.Repository, 0, len(repoIDs))
	if len(repoIDs) == 0 {
		return repos, nil
	}

	return repos, db.GetEngine(env.ctx).
		In("`repository`.id", repoIDs).
		OrderBy(string(env.orderBy)).
		Find(&repos)
}

func (env *accessibleReposEnv) MirrorRepoIDs() ([]int64, error) {
	repoIDs := make([]int64, 0, 10)
	return repoIDs, db.GetEngine(env.ctx).
		Table("repository").
		Join("INNER", "team_repo", "`team_repo`.repo_id=`repository`.id AND `repository`.is_mirror=?", true).
		Where(env.cond()).
		GroupBy("`repository`.id, `repository`.updated_unix").
		OrderBy(string(env.orderBy)).
		Cols("`repository`.id").
		Find(&repoIDs)
}

func (env *accessibleReposEnv) MirrorRepos() (repo_model.RepositoryList, error) {
	repoIDs, err := env.MirrorRepoIDs()
	if err != nil {
		return nil, fmt.Errorf("MirrorRepoIDs: %w", err)
	}

	repos := make([]*repo_model.Repository, 0, len(repoIDs))
	if len(repoIDs) == 0 {
		return repos, nil
	}

	return repos, db.GetEngine(env.ctx).
		In("`repository`.id", repoIDs).
		Find(&repos)
}

func (env *accessibleReposEnv) AddKeyword(keyword string) {
	env.keyword = keyword
}

func (env *accessibleReposEnv) SetSort(orderBy db.SearchOrderBy) {
	env.orderBy = orderBy
}
