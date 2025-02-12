import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Post, Comment
from django.contrib.auth.models import User
from .serializers import UserSerializer, PostSerializer, CommentSerializer
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from rest_framework.authtoken.models import Token
from django.db import IntegrityError
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated

# Index View
def index(request):
    return render(request, 'index.html')
# Sign Up View
def sign_up(request):
    return render(request, 'sign-up.html')

# Index View
def home(request):
    return render(request, 'home.html')



# Get users
def get_users(request):
    try:
        users = list(User.objects.values('id', 'username', 'email', 'created_at'))
        return JsonResponse(users, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
# Get posts
def get_posts(request):
    try:
        posts = Post.objects.all()
        posts_with_comments = []
        for post in posts:
            comments = Comment.objects.filter(post=post)
            comments_with_authors = []
            for comment in comments:
                author = User.objects.get(id=comment.author.id)
                comment_data = {
                    'id': comment.id,
                    'text': comment.text,
                    'author': {
                        'id': author.id,
                        'username': author.username,
                        'email': author.email,
                        'created_at': author.created_at
                    },
                    'created_at': comment.created_at
                }
                comments_with_authors.append(comment_data)
            post_data = {
                'id': post.id,
                'content': post.content,
                'author': {
                    'id': post.author.id,
                    'username': post.author.username,
                    'email': post.author.email,
                    'created_at': post.author.created_at
                },
                'created_at': post.created_at,
                'comments': comments_with_authors
            }
            posts_with_comments.append(post_data)
        return JsonResponse(posts_with_comments, safe=False)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# Login
@csrf_exempt
def login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return JsonResponse({'error': 'Username and password are required'}, status=400)

            user = User.objects.get(username=username)
            if check_password(password, user.password):
                print(f"User found: {user}")  # Check if the user is valid
                try:
                    token, created = Token.objects.get_or_create(user=user)
                    return JsonResponse({'message': 'Login successful', 'token': token.key}, status=200)
                except IntegrityError as e:
                    return JsonResponse({'error': 'Token creation failed due to an integrity error', 'details': str(e)}, status=500)
            else:
                return JsonResponse({'error': 'Invalid password'}, status=400)
        
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# Logout
def logout(request):
    if request.method == 'POST':
        try:
            token = request.data.get('token')
            Token.objects.filter(key=token).delete()
            return JsonResponse({'message': 'Logout successful'}, status=200)
        except Token.DoesNotExist:
            return JsonResponse({'error': 'Invalid token'}, status=400)
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# User API
class UserListCreate(APIView):
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(
            {
                'status': 'success',
                'users': serializer.data,
                'code': status.HTTP_200_OK,
            }
        )

    def post(self, request):
        data = request.data
        if 'password' not in data:
            return Response(
                {
                    'status': 'failure',
                    'errors': 'Password is required',
                    'code': status.HTTP_400_BAD_REQUEST
                }
            )
        
        # Hash the password and print it
        data['password'] = make_password(data['password'])  
        print("Hashed password before saving:", data['password'])
        
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            print("Saved user password:", user.password)  # Check what is saved in the DB
            return Response(
                {
                    'status': 'success',
                    'user': serializer.data,
                    'code': status.HTTP_201_CREATED
                }
            )
        return Response(
            {
                'status': 'failure',
                'errors': serializer.errors,
                'code': status.HTTP_400_BAD_REQUEST
            }
        )


    def put(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'User not found',
                    'code': status.HTTP_404_NOT_FOUND
                }
            )

        data = request.data
        if 'password' in data:
            data['password'] = make_password(data['password'])  # Hash the new password if provided
        serializer = UserSerializer(user, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    'status': 'success',
                    'user': serializer.data,
                    'code': status.HTTP_200_OK
                }
            )
        return Response(
            {
                'status': 'failure',
                'errors': serializer.errors,
                'code': status.HTTP_400_BAD_REQUEST
            }
        )

    def delete(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response(
                {
                    'error': 'User not found',
                    'code': status.HTTP_404_NOT_FOUND
                 })

        user.delete()
        return Response(
            {
                'status': 'success',
                'message': 'User deleted successfully',
                'code': status.HTTP_204_NO_CONTENT
            })

# Post API
class PostListCreate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(
                {
                    'status': 'success',
                    'posts': serializer.data,
                    'code': status.HTTP_200_OK
                })

    def post(self, request):
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    'status': 'success',
                    'post': serializer.data,
                    'code': status.HTTP_201_CREATED
                })
        return Response(
            {
                'status': 'failure',
                'errors': serializer.errors,
                'code': status.HTTP_400_BAD_REQUEST
            })

    def put(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            return Response(
                 {
                    'status': 'failure',
                    'error': 'Post not found',
                    'code': status.HTTP_404_NOT_FOUND
                 })

        serializer = PostSerializer(post, data=request.data, partial=True) 
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    'status': 'success',
                    'post': serializer.data,
                    'code': status.HTTP_200_OK
                })
        return Response(
            {
                'status': 'failure',
                'errors': serializer.errors,
                'code': status.HTTP_400_BAD_REQUEST
            })

    def delete(self, request, pk):
        try:
            post = Post.objects.get(pk=pk)
        except Post.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'Post not found',
                    'code': status.HTTP_404_NOT_FOUND
                })

        post.delete()
        return Response(
            {
                'status': 'success',
                'message': 'Post deleted successfully',
                'code': status.HTTP_204_NO_CONTENT
            })

# Comment API
class CommentListCreate(APIView):
    def get(self, request):
        comments = Comment.objects.all()
        serializer = CommentSerializer(comments, many=True)
        return Response(
            {
                'status': 'success',
                'comments': serializer.data,
                'code': status.HTTP_200_OK
            })

    def post(self, request):
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    'status': 'success',
                    'comment': serializer.data,
                    'code': status.HTTP_201_CREATED
                })
        return Response(
            {
                'status': 'failure',
                'errors': serializer.errors,
                'code': status.HTTP_400_BAD_REQUEST
            })

    def put(self, request, pk):
        
        try:
            comment = Comment.objects.get(pk=pk)
        except Comment.DoesNotExist:
            return Response({'error': 'Comment not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = CommentSerializer(comment, data=request.data, partial=True)  
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    'status': 'success',
                    'comment': serializer.data,
                    'code': status.HTTP_200_OK
                })
        return Response(
            {
                'status': 'failure',
                'errors': serializer.errors,
                'code': status.HTTP_400_BAD_REQUEST
            })

    def delete(self, request, pk):
        try:
            comment = Comment.objects.get(pk=pk)
        except Comment.DoesNotExist:
            return Response(
                {
                    'status': 'failure',
                    'error': 'Comment not found',
                    'code': status.HTTP_404_NOT_FOUND
                })
                    

        comment.delete()
        return Response(
            {
                'status': 'success',
                'message': 'Comment deleted successfully',
                'code': status.HTTP_204_NO_CONTENT
            })
