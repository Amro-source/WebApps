from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import Post
from .forms import PostForm

def home(request):
    """Display all blog posts on the homepage"""
    context = {
        'posts': Post.objects.all().order_by('-date_posted')  # Newest first
    }
    return render(request, 'blog/home.html', context)

def post_create(request):
    """Handle creation of new blog posts"""
    if request.method == 'POST':
        form = PostForm(request.POST)
        if form.is_valid():
            # Set the author before saving
            post = form.save(commit=False)
            post.author = request.user
            post.save()
            return redirect('blog-home')
    else:
        form = PostForm()
    
    return render(request, 'blog/post_form.html', {'form': form})