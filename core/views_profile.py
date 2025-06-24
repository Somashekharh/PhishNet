from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash, logout, get_user_model
from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import ValidationError
from django.db.models import Q

User = get_user_model()

@login_required
def profile(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'update_profile':
            # Update profile information
            user = request.user
            new_email = request.POST.get('email')
            
            # Check if email is already taken by another user
            if User.objects.filter(Q(email=new_email) & ~Q(id=user.id)).exists():
                messages.error(request, 'This email address is already in use.')
                return redirect('profile')
            
            # Update user information
            user.email = new_email
            user.first_name = request.POST.get('first_name')
            user.last_name = request.POST.get('last_name')
            
            try:
                user.full_clean()  # Validate the model
                user.save()
                messages.success(request, 'Your profile has been updated successfully.')
            except ValidationError as e:
                for field, errors in e.message_dict.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
            
            return redirect('profile')
            
    return render(request, 'profile.html', {'active_tab': 'profile'})

@login_required
def profile_security(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'change_password':
            form = PasswordChangeForm(request.user, request.POST)
            if form.is_valid():
                user = form.save()
                update_session_auth_hash(request, user)
                messages.success(request, 'Your password has been changed successfully.')
                return redirect('profile_security')
            else:
                for error in form.errors.values():
                    messages.error(request, error[0])
    
    return render(request, 'profile.html', {'active_tab': 'security'})

@login_required
def profile_delete(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'delete_account':
            password = request.POST.get('password')
            user = request.user
            
            # Verify password
            if user.check_password(password):
                # Delete the user account and log them out
                user.delete()
                logout(request)  # Add explicit logout
                messages.success(request, 'Your account has been deleted successfully.')
                return redirect('home')
            else:
                messages.error(request, 'Invalid password. Please try again.')
    
    return render(request, 'profile.html', {'active_tab': 'delete'}) 