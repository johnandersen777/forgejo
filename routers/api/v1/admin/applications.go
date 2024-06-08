// Copyright 2015 The Gogs Authors. All rights reserved.
// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"net/http"

	"code.gitea.io/gitea/models/application"
	"code.gitea.io/gitea/models/db"
	user_model "code.gitea.io/gitea/models/user"
	api "code.gitea.io/gitea/modules/structs"
	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/routers/api/v1/utils"
	"code.gitea.io/gitea/services/context"
	"code.gitea.io/gitea/services/convert"
)

// CreateApplication api for create application
func CreateApplication(ctx *context.APIContext) {
	// swagger:operation POST /admin/users/{username}/applications admin adminCreateApplication
	// ---
	// summary: Create an application
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: username
	//   in: path
	//   description: username of the user that will own the created application
	//   type: string
	//   required: true
	// - name: application
	//   in: body
	//   required: true
	//   schema: { "$ref": "#/definitions/CreateApplicationOption" }
	// responses:
	//   "201":
	//     "$ref": "#/responses/Application"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"

	form := web.GetForm(ctx).(*api.CreateApplicationOption)

	visibility := api.VisibleTypePublic
	if form.Visibility != "" {
		visibility = api.VisibilityModes[form.Visibility]
	}

	application := &application.Application{
		Name:        form.UserName,
		FullName:    form.FullName,
		Description: form.Description,
		Website:     form.Website,
		Location:    form.Location,
		IsActive:    true,
		Type:        user_model.UserTypeApplication,
		Visibility:  visibility,
	}

	if err := application.CreateApplication(ctx, application, ctx.ContextUser); err != nil {
		if user_model.IsErrUserAlreadyExist(err) ||
			db.IsErrNameReserved(err) ||
			db.IsErrNameCharsNotAllowed(err) ||
			db.IsErrNamePatternNotAllowed(err) {
			ctx.Error(http.StatusUnprocessableEntity, "", err)
		} else {
			ctx.Error(http.StatusInternalServerError, "CreateApplication", err)
		}
		return
	}

	ctx.JSON(http.StatusCreated, convert.ToApplication(ctx, application))
}

// GetAllApplications API for getting information of all the applications
func GetAllApplications(ctx *context.APIContext) {
	// swagger:operation GET /admin/applications admin adminGetAllApplications
	// ---
	// summary: List all applications
	// produces:
	// - application/json
	// parameters:
	// - name: page
	//   in: query
	//   description: page number of results to return (1-based)
	//   type: integer
	// - name: limit
	//   in: query
	//   description: page size of results
	//   type: integer
	// responses:
	//   "200":
	//     "$ref": "#/responses/ApplicationList"
	//   "403":
	//     "$ref": "#/responses/forbidden"

	listOptions := utils.GetListOptions(ctx)

	users, maxResults, err := user_model.SearchUsers(ctx, &user_model.SearchUserOptions{
		Actor:       ctx.Doer,
		Type:        user_model.UserTypeApplication,
		OrderBy:     db.SearchOrderByAlphabetically,
		ListOptions: listOptions,
		Visible:     []api.VisibleType{api.VisibleTypePublic, api.VisibleTypeLimited, api.VisibleTypePrivate},
	})
	if err != nil {
		ctx.Error(http.StatusInternalServerError, "SearchApplications", err)
		return
	}
	applications := make([]*api.Application, len(users))
	for i := range users {
		applications[i] = convert.ToApplication(ctx, application.ApplicationFromUser(users[i]))
	}

	ctx.SetLinkHeader(int(maxResults), listOptions.PageSize)
	ctx.SetTotalCountHeader(maxResults)
	ctx.JSON(http.StatusOK, &applications)
}
