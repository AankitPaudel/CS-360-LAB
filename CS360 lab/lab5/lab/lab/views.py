from django.shortcuts import render

def home(request):
    return render(request, 'base.html')

def bio(request):
    return render(request, 'bio.html')

def blog(request):
    return render(request, 'blog.html')

def photos(request):
    return render(request, 'photos.html')

def contact(request):
    return render(request, 'contact.html')
