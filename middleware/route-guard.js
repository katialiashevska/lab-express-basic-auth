// check if the user is logged in when trying to access a page
const isLoggedIn = (req, res, next) => {
    if (!req.session.currentUser) {
        return res.redirect("/login");
    }
    next();
};

// if a logged in user tries to access log in or sign up, redirect to the home page
const isLoggedOut = (req, res, next) => {
    if (req.session.currentUser) {
        return res.redirect("/userProfile");
    }
    next();
};

module.exports = {
    isLoggedIn,
    isLoggedOut
};
