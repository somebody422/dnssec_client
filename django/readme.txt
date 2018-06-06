

"manage.py" should be used for server changes/administration.

'python manage.py startapp APP' - create a new app and initialize with some default stuff.

View - Converts a request into a response. Response can be a page, image, document, whatever. Usually a page. Although these can be anywhere in the Python path, they are usualy organized by app into view.py files


Model - A piece of information, or data-related object. Usually each model subclass represents a database table.
A useful thing is ModelSubclass.objects to get a list of instantiated objects


'python manage.py shell' will esentially start a python shell and run 'import django' 'django.setup()'.

HTML templates - Django by default uses its own template system. The page for it suggests django can use other systems
https://docs.djangoproject.com/en/1.11/topics/templates/
* Try to avoid hard-coding URLs in templates, use names instead. see: https://docs.djangoproject.com/en/1.11/intro/tutorial03/


Path a user takes in the tutorial1 voting poll app (as of mid-tutorial section 4):
* GET polls/
server responds with "index" view and index.html, showing a list of questions
* GET polls/1
User clicks on question 1, sends this request.
Server responds with 'detail' view and detail.html
* POST polls/1/vote
User clicks vote, sending the POST data.
Server uses "vote" view, which expects POST data.
If the user didn't select a box, will respond with detail.html (with an error message)
Otherwise, the server does a redirect to polls:results
* GET polls/1/results
Server responds with question 1 info


Generic views - subclass you view classes with a generic view to speed up development. A lot of the time your views will just be an HTML page with database info filled in. Generic views will do that (with a bit of customization) quickly/easily
https://docs.djangoproject.com/en/1.11/ref/class-based-views/generic-display/



